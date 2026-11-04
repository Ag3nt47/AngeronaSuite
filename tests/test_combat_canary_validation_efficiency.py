"""Avoid duplicate scope work without skipping current issuer/native guards."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from test_redteam_fix_pipeline import source_canary
from test_soar_issuer_delegation import issuer

from angerona.core.eventbus import Event, Severity
from angerona.core.practice_verification import _publish_process_probe, _retire_process
from angerona.core import windows_process_lease
from angerona.modules import adversary_combat as combat, purple_guard as purple


@pytest.fixture(params=["file", "process"])
def live_canary(request):
    """Keep the actual enrolled object, detector receipt and issuer checks."""
    ctx = request.getfixturevalue("issuer" if request.param == "file" else "source_canary")
    process = None
    try:
        event = ctx.event
        operation = "quarantine_file"
        if request.param == "process":
            operation = "terminate_process"
            _binding, process = _publish_process_probe(ctx.bus, ctx.run_id, lease=ctx.lease)
            deadline = time.monotonic() + 5
            event = None
            while event is None and time.monotonic() < deadline:
                ctx.guard.scan_process_once(ctx.guard._policy_snapshot())
                event = next((row for row in reversed(ctx.bus.recent(200))
                              if row.module == ctx.guard.name
                              and row.details.get("pid") == process.pid
                              and row.details.get("receipt_type") == "purple_simulation_validation"),
                             None)
                if event is None:
                    time.sleep(.02)
            assert event is not None, "The real child must receive its actual detector receipt"
        assert ctx.bus.verify(event)
        proof = ctx.combat._practice_mutation(event, operation)
        assert proof is not None, "The positive must pass the real issuer admission"
        yield SimpleNamespace(ctx=ctx, event=event, proof=proof, process=process)
    finally:
        if process is not None:
            assert _retire_process(process)


def _count_real_validation(monkeypatch):
    owner = threading.get_ident()
    scope_results, verifications = [], []
    real_scope = purple.RedTeamValidationLease._state_matches
    real_verify = purple.verify_validation_purple_event

    def scope(lease):
        result = real_scope(lease)
        if threading.get_ident() == owner:
            scope_results.append(result)
        return result

    def verify(lease, event, step):
        if threading.get_ident() == owner:
            verifications.append((lease, event, step))
        return real_verify(lease, event, step)

    monkeypatch.setattr(purple.RedTeamValidationLease, "_state_matches", scope)
    monkeypatch.setattr(purple, "verify_validation_purple_event", verify)
    return scope_results, verifications


def _trace_bad_inner_receipt_refusals(monkeypatch, scope_checks):
    """Observe the real captured helper's MAC refusal; never replace its result."""
    owner = threading.get_ident()
    original_code = purple._QueuedFileReobservations._original.__code__
    actual_compare = purple.hmac.compare_digest
    refusals = []

    def compare(supplied, expected):
        result = actual_compare(supplied, expected)
        if (threading.get_ident() == owner
                and sys._getframe(1).f_code is original_code
                and supplied == "0" * 64):
            refusals.append((result, tuple(scope_checks)))
        return result

    monkeypatch.setattr(purple.hmac, "compare_digest", compare)
    return refusals


def test_each_normal_canary_recheck_validates_full_scope_once(live_canary, monkeypatch):
    case = live_canary
    checks, verifications = _count_real_validation(monkeypatch)
    for index in range(2):
        assert case.ctx.combat._canary_mutation_valid(case.proof)
        assert checks == [True] * (index + 1)
        assert len(verifications) == index + 1
        assert verifications[-1] == (
            case.ctx.lease, case.proof.event,
            {"attack_ids": [case.event.details["technique"]]},
        )


def test_normal_canary_real_scope_revocation_still_denies(live_canary, monkeypatch):
    case = live_canary
    checks, verifications = _count_real_validation(monkeypatch)
    policy = purple.policy_path(case.ctx.combat.data_root)
    original = policy.read_bytes()
    try:
        # Valid JSON with a different authenticated scope identity. Neither the
        # issuer verifier nor its acceptance result is replaced by the test.
        policy.write_bytes(original + b"\n")
        assert not case.ctx.combat._canary_mutation_valid(case.proof)
        assert checks == [False]
        assert len(verifications) == 1
    finally:
        policy.write_bytes(original)


def test_exclusive_handoff_retains_full_scope_actual_pin_and_mac(source_canary, monkeypatch):
    ctx = source_canary
    proof = ctx.combat._practice_mutation(ctx.event, "quarantine_file")
    assert proof is not None
    purple.RedTeamValidationLease.begin_marker_containment(
        ctx.lease, ctx.combat, ctx.event, ctx.marker,
    )
    try:
        with combat._PinnedFileMove(ctx.marker) as pinned:
            checks, verifications = _count_real_validation(monkeypatch)
            assert ctx.combat._canary_mutation_valid(proof, pinned=pinned)
            assert not ctx.combat._canary_mutation_valid(proof)
            assert not ctx.combat._canary_mutation_valid(proof, pinned=object())
            assert checks == [True] * 3  # Each genuine handoff recheck retains full scope.
            before_forgery = tuple(checks)
            altered = replace(proof.event, details={
                **proof.event.details, "detector_receipt_mac": "0" * 64,
            })
            altered = replace(altered, hmac_sig=ctx.recorder.authority.sign(altered))
            assert ctx.bus.verify(altered), "Reach the inner issuer HMAC boundary"
            forged = replace(proof, event=altered, signature=altered.hmac_sig)
            refusals = _trace_bad_inner_receipt_refusals(monkeypatch, checks)
            for method in ("require_single_link", "sha256", "duplicate_custody_descriptor"):
                monkeypatch.setattr(pinned, method, _forbidden)
            assert not ctx.combat._canary_mutation_valid(forged, pinned=pinned)
            # The mandatory captured helper now rejects the actual bad inner MAC
            # before potentially blocking scope work or any native pin inspection.
            assert refusals and all(result is False and seen == before_forgery
                                    for result, seen in refusals)
            assert tuple(checks) == before_forgery
            assert verifications == []
    finally:
        purple.RedTeamValidationLease.abort_marker_containment(
            ctx.lease, ctx.combat, ctx.marker, recapture=True,
        )


def test_exclusive_handoff_rejects_revoked_scope_before_native_pin(source_canary, monkeypatch):
    ctx = source_canary
    proof = ctx.combat._practice_mutation(ctx.event, "quarantine_file")
    assert proof is not None
    purple.RedTeamValidationLease.begin_marker_containment(
        ctx.lease, ctx.combat, ctx.event, ctx.marker,
    )
    policy = purple.policy_path(ctx.combat.data_root)
    original = policy.read_bytes()
    try:
        with combat._PinnedFileMove(ctx.marker) as pinned:
            checks, verifications = _count_real_validation(monkeypatch)
            for method in ("require_single_link", "sha256", "duplicate_custody_descriptor"):
                monkeypatch.setattr(combat._PinnedFileMove, method, _forbidden)
            policy.write_bytes(original + b"\n")
            assert not ctx.combat._canary_mutation_valid(proof, pinned=pinned)
            assert checks == [False]
            assert verifications == []
    finally:
        policy.write_bytes(original)
        purple.RedTeamValidationLease.abort_marker_containment(
            ctx.lease, ctx.combat, ctx.marker, recapture=True,
        )


def _forbidden(*_args, **_kwargs):
    pytest.fail("The rejected request reached proof, policy or a native adapter")


def _no_process_work(monkeypatch):
    module = object.__new__(combat.AdversaryCombat)
    for method in ("_practice_mutation", "_host_mutation_allowed", "policy"):
        monkeypatch.setattr(module, method, _forbidden)
    monkeypatch.setattr(combat, "psutil", SimpleNamespace(Process=_forbidden))
    monkeypatch.setattr(windows_process_lease, "_Native", _forbidden)
    return module


@pytest.mark.parametrize("pid", [None, 0, -1, True, 1.0, "123"])
def test_invalid_pid_never_constructs_proof_or_native_authority(monkeypatch, pid):
    module = _no_process_work(monkeypatch)
    assert module._act_on_process(
        pid, combat.CombatPolicy(), Event("Inert", "invalid target", Severity.HIGH), "c",
    ) is None


def test_missing_psutil_never_constructs_proof_or_native_authority(monkeypatch):
    module = _no_process_work(monkeypatch)
    monkeypatch.setattr(combat, "psutil", None)
    assert module._act_on_process(
        999999, combat.CombatPolicy(), Event("Inert", "unavailable target", Severity.HIGH), "c",
    ) is None


@pytest.mark.parametrize("allowed", [frozenset(), frozenset({"quarantine_file"}),
                                  frozenset({"block_remote_ip", "isolate_host", "activate_honeypots"})])
def test_explicit_non_process_contract_never_constructs_authority(monkeypatch, allowed):
    module = _no_process_work(monkeypatch)
    assert module._act_on_process(
        999999, combat.CombatPolicy(), Event("Inert", "other actions", Severity.HIGH), "c",
        allowed_actions=allowed,
    ) is None


@pytest.mark.parametrize("allowed", [None, frozenset({"terminate_process"}),
                                  frozenset({"suspend_process"}), frozenset({"isolate_program"})])
def test_process_contracts_and_legacy_default_reach_real_current_policy_guard(
    source_canary, monkeypatch, allowed,
):
    ctx = source_canary
    _binding, process = _publish_process_probe(ctx.bus, ctx.run_id, lease=ctx.lease)
    try:
        deadline = time.monotonic() + 5
        event = None
        while event is None and time.monotonic() < deadline:
            ctx.guard.scan_process_once(ctx.guard._policy_snapshot())
            event = next((row for row in reversed(ctx.bus.recent(200))
                          if row.module == ctx.guard.name and row.details.get("pid") == process.pid
                          and row.details.get("receipt_type") == "purple_simulation_validation"), None)
            if event is None:
                time.sleep(.02)
        assert event is not None
        practice, authority = ctx.combat._practice_mutation, ctx.combat._host_mutation_allowed
        admitted = []

        def real_practice(*args, **kwargs):
            proof = practice(*args, **kwargs)
            assert proof is not None
            admitted.append("proof")
            return proof

        def real_authority(*args, **kwargs):
            result = authority(*args, **kwargs)
            assert result is True
            admitted.append("authority")
            return result

        monkeypatch.setattr(ctx.combat, "_practice_mutation", real_practice)
        monkeypatch.setattr(ctx.combat, "_host_mutation_allowed", real_authority)
        monkeypatch.setattr(combat, "psutil", SimpleNamespace(Process=_forbidden))
        monkeypatch.setattr(windows_process_lease, "_Native", _forbidden)
        policy = ctx.combat.policy()
        assert ctx.combat._act_on_process(
            process.pid, policy, event, "c", allowed_actions=allowed,
            expected_policy=replace(policy, enabled=False),
        ) is None
        assert admitted == ["proof", "authority"]
        assert process.poll() is None
    finally:
        assert _retire_process(process)


@contextmanager
def _retained_marker_boundary(ctx, *, install_context=True):
    """Genuine issuer handoff and exclusive native pin; no file is moved."""
    proof = ctx.combat._practice_mutation(ctx.event, "quarantine_file")
    assert proof is not None
    purple.RedTeamValidationLease.begin_marker_containment(
        ctx.lease, ctx.combat, ctx.event, ctx.marker,
    )
    previous = getattr(ctx.combat._response_dispatch_local, "context", None)
    try:
        with combat._PinnedFileMove(ctx.marker) as pinned:
            combat_id = "combat-777777777777"
            action = ctx.combat._action("quarantine_file", str(ctx.marker), ctx.event,
                combat_id, reversible=True, details={
                    "original": str(ctx.marker),
                    "quarantine": str(ctx.combat.quarantine_root / combat_id / ctx.marker.name),
                    "sha256": proof.identity["sha256"], "file_identity": pinned.identity,
                    "source_identity": pinned.identity, "source_link_count": 1,
                    "move_strategy": "rename",
                })
            retained = (ctx.event, proof, action, pinned)
            if install_context:
                ctx.combat._response_dispatch_local.context = retained
            yield SimpleNamespace(proof=proof, action=action, pinned=pinned, retained=retained)
    finally:
        ctx.combat._response_dispatch_local.context = previous
        purple.RedTeamValidationLease.abort_marker_containment(
            ctx.lease, ctx.combat, ctx.marker, recapture=True,
        )


def test_exact_retained_file_guard_runs_full_fresh_scope_once_per_call(
    source_canary, monkeypatch,
):
    from angerona.core.threat import event_disposition
    ctx = source_canary
    # The real Purple v2 contract does not supply the generic file-identity
    # practice fields. Its classification cannot replace issuer authority.
    assert "observed_file_identity" not in ctx.event.details
    assert event_disposition(ctx.event) == "active"
    with _retained_marker_boundary(ctx) as bound:
        checks, verifications = _count_real_validation(monkeypatch)
        actual_current = ctx.combat._require_current_response_event
        actual_canary = ctx.combat._canary_mutation_valid
        route = []

        def current(event, **kwargs):
            frame = sys._getframe(1)
            try:
                assert frame.f_code is combat.AdversaryCombat._require_host_mutation_authority.__code__
                route.append(("current", frame.f_locals.get("deferred_canary"),
                              kwargs.get("require_canary")))
            finally:
                del frame
            return actual_current(event, **kwargs)

        def canary(proof, **kwargs):
            route.append(("canary", proof is bound.proof))
            return actual_canary(proof, **kwargs)

        monkeypatch.setattr(ctx.combat, "_require_current_response_event", current)
        monkeypatch.setattr(ctx.combat, "_canary_mutation_valid", canary)
        for index in range(2):
            ctx.combat._require_host_mutation_authority(
                canary=bound.proof, action=bound.action, pinned=bound.pinned,
            )
            assert checks == [True] * (index + 1)
            assert verifications == []  # Handoff uses the exact native pin + issuer MAC.
            assert ctx.combat._host_authority_verified is False
            assert route == [("current", True, True), ("canary", True)] * (index + 1)
    assert ctx.marker.is_file(), "A guard-only test must not manufacture containment"


@pytest.mark.parametrize("different", ["canary", "action", "pin"])
def test_nonidentical_dispatch_arguments_cannot_use_the_combined_guard(
    source_canary, monkeypatch, different,
):
    ctx = source_canary
    with _retained_marker_boundary(ctx) as bound:
        checks, _verifications = _count_real_validation(monkeypatch)
        actual_canary = ctx.combat._canary_mutation_valid
        actual_current = ctx.combat._require_current_response_event
        route = []

        def validate(proof, **kwargs):
            observed = dict(kind="canary", proof=proof, **kwargs)
            route.append(observed)
            observed["result"] = actual_canary(proof, **kwargs)
            return observed["result"]

        def current(event, **kwargs):
            route.append(dict(kind="current", event=event, **kwargs))
            return actual_current(event, **kwargs)

        monkeypatch.setattr(ctx.combat, "_canary_mutation_valid", validate)
        monkeypatch.setattr(ctx.combat, "_require_current_response_event", current)
        arguments = dict(canary=bound.proof, action=bound.action, pinned=bound.pinned)
        if different == "canary":
            arguments["canary"] = replace(bound.proof)
        elif different == "action":
            arguments["action"] = replace(bound.action)
        else:
            arguments["pinned"] = None
        if different == "pin":
            with pytest.raises(combat.HostMutationHeld):
                ctx.combat._require_host_mutation_authority(**arguments)
            assert route and route[0]["kind"] == "canary"
            assert route[0]["result"] is False
            assert not any(row["kind"] == "current" for row in route)
        else:
            ctx.combat._require_host_mutation_authority(**arguments)
            assert route and route[0]["kind"] == "canary"
            assert route[0]["result"] is True
            final = next(row for row in route if row["kind"] == "current")
            assert final["event"] is ctx.event and final["canary"] is bound.proof
            assert final["action"] is arguments["action"] and final["pinned"] is bound.pinned
        # Distinct request objects must receive their own genuine validation
        # BEFORE the final current-event route. That route may classify the
        # exclusively pinned file as active, so duplicate scope work is not
        # assumed. Both wrappers above delegate to the actual guard methods.
        assert route[0]["proof"] is arguments["canary"]
        assert route[0]["action"] is arguments["action"]
        assert route[0]["pinned"] is arguments["pinned"]
        assert checks and all(checks)
        assert _verifications == []
        assert ctx.combat._host_authority_verified is False
    assert ctx.marker.is_file()


def test_active_dispatch_cannot_defer_a_practice_canary_scope_check(source_canary, monkeypatch):
    from angerona.core.threat import event_disposition
    ctx = source_canary
    with _retained_marker_boundary(ctx) as bound:
        active = Event("Inert Native Detector", "guard-only active envelope", Severity.HIGH,
                       details={"active_attack": True})
        active = replace(active, hmac_sig=ctx.recorder.authority.sign(active))
        assert ctx.bus.verify(active) and event_disposition(active) == "active"
        ctx.combat._response_dispatch_local.context = (
            active, bound.proof, bound.action, bound.pinned,
        )
        checks, _verifications = _count_real_validation(monkeypatch)
        ctx.combat._require_host_mutation_authority(
            canary=bound.proof, action=bound.action, pinned=bound.pinned,
        )
        assert checks == [True]  # Active's final verifier cannot substitute this check.
    assert ctx.marker.is_file()


def test_revoked_scope_denies_before_native_pin_and_clears_host_authority(
    source_canary, monkeypatch,
):
    ctx = source_canary
    with _retained_marker_boundary(ctx) as bound:
        checks, _verifications = _count_real_validation(monkeypatch)
        policy = purple.policy_path(ctx.root)
        original = policy.read_bytes()
        try:
            for name in ("require_single_link", "sha256", "duplicate_custody_descriptor"):
                monkeypatch.setattr(combat._PinnedFileMove, name, _forbidden)
            policy.write_bytes(original + b"\n")
            ctx.combat._host_authority_verified = True
            ctx.combat._host_authority_reason = ""
            # Whether denial occurs at the source-authority fallback or the
            # final issuer guard, revoked scope must not reach native work or
            # preserve the deliberately seeded older Protect observation.
            with pytest.raises(combat.HostMutationHeld):
                ctx.combat._require_host_mutation_authority(
                    canary=bound.proof, action=bound.action, pinned=bound.pinned,
                )
            assert checks == [False]
            assert ctx.combat._host_authority_verified is False
            assert ctx.combat._host_authority_reason == "Source Observe"
        finally:
            policy.write_bytes(original)
    assert ctx.marker.is_file()


@pytest.mark.parametrize("change", ["expired", "stop", "policy"])
def test_combined_guard_rechecks_late_freshness_generation_and_full_policy(
    source_canary, monkeypatch, change,
):
    ctx = source_canary
    with _retained_marker_boundary(ctx) as bound:
        checks, _verifications = _count_real_validation(monkeypatch)
        original_current = ctx.combat._require_current_response_event
        original_policy, original_clock = ctx.combat.policy(), combat.time

        def current_then_change(*args, **kwargs):
            result = original_current(*args, **kwargs)
            if change == "expired":
                class AfterProofClock:
                    def time(self):
                        return ctx.event.ts + 31
                    def __getattr__(self, name):
                        return getattr(original_clock, name)
                monkeypatch.setattr(combat, "time", AfterProofClock())
            elif change == "stop":
                ctx.combat.stop()
            else:
                monkeypatch.setattr(ctx.combat, "policy", lambda: replace(
                    original_policy, min_severity=Severity.CRITICAL))
            return result

        monkeypatch.setattr(ctx.combat, "_require_current_response_event", current_then_change)
        # A failed canary must not preserve an older successful Protect sample.
        ctx.combat._host_authority_verified = True
        ctx.combat._host_authority_reason = ""
        with pytest.raises(combat.HostMutationHeld):
            ctx.combat._require_host_mutation_authority(
                canary=bound.proof, action=bound.action, pinned=bound.pinned,
            )
        assert checks == [True]  # Genuine full proof ran before the late change.
        assert ctx.combat._host_authority_verified is False
        assert "Source Observe" in ctx.combat._host_authority_reason
    assert ctx.marker.is_file()


def test_post_intent_and_final_dispatch_each_keep_one_full_scope_check(
    source_canary, monkeypatch,
):
    ctx = source_canary
    with _retained_marker_boundary(ctx, install_context=False) as bound:
        checks, _verifications = _count_real_validation(monkeypatch)
        try:
            with ctx.combat._journaled_mutation(bound.action, canary=bound.proof,
                    pinned=bound.pinned, event=ctx.event):
                assert checks == [True, True]  # Before intent, then current post-intent proof.
                assert ctx.combat._response_dispatch_local.context == bound.retained
                ctx.combat._require_host_mutation_authority(
                    canary=bound.proof, action=bound.action, pinned=bound.pinned,
                )
                assert checks == [True, True, True]  # A later native barrier checks again.
            assert getattr(ctx.combat._response_dispatch_local, "context", None) is None
        finally:
            ctx.combat._journal_failure(bound.action, "inert guard-only intent; no effect was attempted")
    assert ctx.marker.is_file()


def test_post_intent_guard_failure_restores_exact_previous_dispatch(source_canary, monkeypatch):
    ctx = source_canary
    with _retained_marker_boundary(ctx) as bound:
        previous = ctx.combat._response_dispatch_local.context
        written = []
        original_intent = ctx.combat._journal_intent
        original_current = ctx.combat._require_current_response_event

        def intent(action):
            result = original_intent(action)
            written.append(action.action_id)
            return result

        def fail_after_current(*args, **kwargs):
            result = original_current(*args, **kwargs)
            if written:
                raise combat.HostMutationHeld("inert refusal after genuine current proof")
            return result

        monkeypatch.setattr(ctx.combat, "_journal_intent", intent)
        monkeypatch.setattr(ctx.combat, "_require_current_response_event", fail_after_current)
        try:
            with pytest.raises(combat.HostMutationHeld, match="inert refusal"):
                with ctx.combat._journaled_mutation(bound.action, canary=bound.proof,
                        pinned=bound.pinned, event=ctx.event):
                    pytest.fail("A refused final guard entered its effect body")
            assert len(written) == 1
            assert ctx.combat._response_dispatch_local.context is previous
        finally:
            ctx.combat._journal_failure(bound.action, "inert guard refusal; no effect was attempted")
    assert ctx.marker.is_file()


def test_pre_pin_binding_combines_real_scope_and_host_admission_once(source_canary, monkeypatch):
    ctx = source_canary
    checks, verifications = _count_real_validation(monkeypatch)
    host = ctx.combat._require_host_mutation_authority
    admissions = []

    def real_host(**kwargs):
        admissions.append(kwargs.get("require_canary"))
        return host(**kwargs)

    monkeypatch.setattr(ctx.combat, "_require_host_mutation_authority", real_host)
    for index in range(2):
        proof = ctx.combat._practice_mutation(ctx.event, "quarantine_file", require_host=True)
        assert proof is not None and proof.signature == ctx.event.hmac_sig
        assert checks == [True] * (index + 1)
        assert len(verifications) == index + 1
        assert admissions == [True] * (index + 1)
        assert ctx.combat._host_authority_verified is False
    assert ctx.marker.is_file()


def test_required_canary_refuses_revocation_even_if_host_authority_is_present(source_canary, monkeypatch):
    ctx = source_canary
    proof = ctx.combat._practice_mutation(ctx.event, "quarantine_file")
    assert proof is not None
    checks, verifications = _count_real_validation(monkeypatch)
    # Inert privilege result only: this negative must still fail the actual
    # issuer policy/scope check, and never invokes a host-effect adapter.
    monkeypatch.setattr("angerona.core.breach_state.protect_authority", lambda: (True, "Inert host boundary"))
    policy = purple.policy_path(ctx.root)
    original = policy.read_bytes()
    try:
        policy.write_bytes(original + b"\n")
        with pytest.raises(combat.HostMutationHeld):
            ctx.combat._require_host_mutation_authority(canary=proof, require_canary=True)
        assert checks == [False] and len(verifications) == 1
        assert ctx.combat._host_authority_verified is False
        with pytest.raises(combat.HostMutationHeld):
            ctx.combat._practice_mutation(ctx.event, "quarantine_file", require_host=True)
        assert checks == [False, False]
    finally:
        policy.write_bytes(original)
    assert ctx.marker.is_file()


def test_required_current_canary_cannot_borrow_another_signed_active_event(source_canary, monkeypatch):
    ctx = source_canary
    with _retained_marker_boundary(ctx) as bound:
        active = Event("Inert Native Detector", "unrelated signed event", Severity.HIGH,
                       details={"active_attack": True})
        active = replace(active, hmac_sig=ctx.recorder.authority.sign(active))
        assert ctx.bus.verify(active)
        checks, _verifications = _count_real_validation(monkeypatch)
        with pytest.raises(combat.HostMutationHeld):
            ctx.combat._require_current_response_event(active, canary=bound.proof,
                action=bound.action, pinned=bound.pinned, require_canary=True)
        assert checks == []
    assert ctx.marker.is_file()


def test_combined_guard_rechecks_scope_after_blocking_classification(source_canary, monkeypatch):
    ctx = source_canary
    with _retained_marker_boundary(ctx) as bound:
        checks, _verifications = _count_real_validation(monkeypatch)
        classify = combat.event_disposition
        policy = purple.policy_path(ctx.root)
        original = policy.read_bytes()
        classified = []

        def classify_then_revoke(event):
            result = classify(event)
            if event is ctx.event and not classified:
                classified.append(result)
                policy.write_bytes(original + b"\n")
            return result

        monkeypatch.setattr(combat, "event_disposition", classify_then_revoke)
        try:
            with pytest.raises(combat.HostMutationHeld):
                ctx.combat._require_host_mutation_authority(
                    canary=bound.proof, action=bound.action, pinned=bound.pinned)
            assert classified == ["active"]
            assert checks == [False]
            assert ctx.combat._host_authority_verified is False
        finally:
            policy.write_bytes(original)
    assert ctx.marker.is_file()


def test_quarantine_holds_refused_recognized_canary_without_protect_fallback(source_canary, monkeypatch):
    ctx = source_canary
    assert ctx.combat._practice_mutation(ctx.event, "quarantine_file") is not None
    checks, _verifications = _count_real_validation(monkeypatch)
    monkeypatch.setattr("angerona.core.breach_state.protect_authority", lambda: (True, "Inert host boundary"))
    monkeypatch.setattr(ctx.combat, "_host_mutation_allowed", _forbidden)
    monkeypatch.setattr(combat._PinnedFileMove, "__init__", _forbidden)
    monkeypatch.setattr(ctx.combat, "_journal_intent", _forbidden)
    policy = purple.policy_path(ctx.root)
    original = policy.read_bytes()
    try:
        policy.write_bytes(original + b"\n")
        assert ctx.combat._quarantine_file(str(ctx.marker), ctx.event, "combat-888888888888") is None
        assert checks == [False]
        assert ctx.combat._host_authority_verified is False
    finally:
        policy.write_bytes(original)
    assert ctx.marker.is_file()


def test_ordinary_noncanary_still_reaches_real_protect_admission(source_canary, monkeypatch):
    ctx = source_canary
    ordinary = ctx.root / "ordinary-detector-control.txt"
    ordinary.write_text("Inert noncanary boundary control", encoding="utf-8")
    event = Event("Inert Native Detector", "ordinary signed detector event", Severity.HIGH,
                  details={"path": str(ordinary), "active_attack": True})
    event = replace(event, hmac_sig=ctx.recorder.authority.sign(event))
    assert ctx.bus.verify(event)
    monkeypatch.setattr("angerona.core.breach_state.protect_authority", lambda: (True, "Inert host boundary"))
    actual_host = ctx.combat._host_mutation_allowed
    admissions, denied_paths = [], []

    def real_host(**kwargs):
        result = actual_host(**kwargs)
        admissions.append((kwargs.get("canary"), result))
        return result

    def protected_refusal(path):
        denied_paths.append(path)
        return True  # Test ends at a denial; no native custody/effect is admitted.

    monkeypatch.setattr(ctx.combat, "_host_mutation_allowed", real_host)
    monkeypatch.setattr(ctx.combat, "_is_protected_file", protected_refusal)
    monkeypatch.setattr(combat._PinnedFileMove, "__init__", _forbidden)
    monkeypatch.setattr(ctx.combat, "_journal_intent", _forbidden)
    assert ctx.combat._quarantine_file(str(ordinary), event, "combat-999999999999") is None
    assert admissions == [(None, True)] and denied_paths == [ordinary]
    assert ordinary.read_text(encoding="utf-8") == "Inert noncanary boundary control"


def test_required_canary_cannot_take_non_authorizing_admission_shortcut(live_canary, monkeypatch):
    from angerona.core.threat import event_disposition
    case = live_canary
    ctx = case.ctx
    disposition = event_disposition(case.event)
    if case.process is not None:
        # This is a genuinely registered nonce-bound process and real detector
        # receipt, so the old practice admission shortcut is actually exercised.
        assert disposition == "practice"
    checks, _verifications = _count_real_validation(monkeypatch)
    policy = purple.policy_path(ctx.combat.data_root)
    original = policy.read_bytes()
    try:
        policy.write_bytes(original + b"\n")
        with pytest.raises(combat.HostMutationHeld):
            ctx.combat._require_current_response_event(case.event, canary=case.proof,
                admission=True, require_canary=True)
        assert checks == [False]
        # Ordinary admission is still non-authorizing. Its old default does
        # not demand this additional supplied canary proof.
        ctx.combat._require_current_response_event(case.event, canary=case.proof, admission=True)
        assert checks == [False]
        if disposition == "practice":
            with pytest.raises(combat.HostMutationHeld):
                ctx.combat._require_current_response_event(case.event, canary=case.proof)
            assert checks == [False, False]
    finally:
        policy.write_bytes(original)
    if case.process is not None:
        assert case.process.poll() is None


def test_real_guard_refusal_before_dispatch_records_failure_without_compensation(source_canary, monkeypatch):
    ctx = source_canary
    before_rows, _legacy = ctx.combat._read_journal(strict=True)
    original_bytes = ctx.marker.read_bytes()
    policy = purple.policy_path(ctx.root)
    original_policy = policy.read_bytes()
    actual_host = ctx.combat._require_host_mutation_authority
    revoked = []

    def revoke_only_at_final_file_guard(**kwargs):
        frame = sys._getframe(1)
        try:
            at_native_boundary = frame.f_code is combat.AdversaryCombat._quarantine_file.__code__
        finally:
            del frame
        if at_native_boundary:
            revoked.append(True)
            policy.write_bytes(original_policy + b"\n")
        return actual_host(**kwargs)

    monkeypatch.setattr(ctx.combat, "_require_host_mutation_authority", revoke_only_at_final_file_guard)
    monkeypatch.setattr(combat._PinnedFileMove, "rename_to", _forbidden)
    monkeypatch.setattr(ctx.combat, "_rollback_uncertain_reversible_mutation", _forbidden)
    monkeypatch.setattr(ctx.combat, "_undo_record", _forbidden)
    monkeypatch.setattr(ctx.combat, "_append_undo_phase", _forbidden)
    try:
        result = ctx.combat._quarantine_file(str(ctx.marker), ctx.event, "combat-121212121212")
        assert result is None and revoked == [True]
    finally:
        policy.write_bytes(original_policy)
    rows, _legacy = ctx.combat._read_journal(strict=True)
    new_rows = rows[len(before_rows):]
    assert [row["record_type"] for row in new_rows] == ["intent", "failure"]
    assert new_rows[0]["action_id"] == new_rows[1]["action_id"]
    assert new_rows[1]["status"] == "failed"
    assert "HostMutationHeld" in new_rows[1]["error"]
    assert ctx.marker.read_bytes() == original_bytes
    assert not (ctx.combat.quarantine_root / "combat-121212121212" / ctx.marker.name).exists()


def test_native_move_then_raise_still_keeps_orphan_and_real_rollback(source_canary, monkeypatch):
    ctx = source_canary
    before_rows, _legacy = ctx.combat._read_journal(strict=True)
    original_bytes = ctx.marker.read_bytes()
    actual_rename = combat._PinnedFileMove.rename_to
    moves = []

    def moved_then_failed(pinned, destination):
        identity = actual_rename(pinned, destination)
        moves.append(destination)
        if len(moves) == 1:
            assert not ctx.marker.exists(), "Fault must follow the actual native move"
            raise OSError("Synthetic failure after the actual native move")
        return identity

    monkeypatch.setattr(combat._PinnedFileMove, "rename_to", moved_then_failed)
    result = ctx.combat._quarantine_file(str(ctx.marker), ctx.event, "combat-343434343434")
    assert result is None
    assert len(moves) == 2 and moves[-1] == ctx.marker
    rows, _legacy = ctx.combat._read_journal(strict=True)
    new_rows = rows[len(before_rows):]
    assert [row["record_type"] for row in new_rows] == ["intent", "orphan", "undo_intent", "undo_commit", "failure"]
    assert all(row["record_type"] != "commit" for row in new_rows)
    assert ctx.marker.read_bytes() == original_bytes
    assert not (ctx.combat.quarantine_root / "combat-343434343434" / ctx.marker.name).exists()


def test_direct_handle_native_purple_file_admits_one_real_scope_before_action(source_canary, monkeypatch):
    from angerona.core.threat import event_disposition
    ctx = source_canary
    assert event_disposition(ctx.event) == "active"
    assert ctx.event.details["redteam_detector_receipt_version"] == 2
    checks, verifications = _count_real_validation(monkeypatch)
    actual_current = ctx.combat._require_current_response_event
    actual_binding = ctx.combat._practice_mutation
    route, denied = [], []

    def current(event, **kwargs):
        route.append(("current", kwargs.get("admission", False)))
        assert checks == []
        return actual_current(event, **kwargs)

    def binding(event, operation, **kwargs):
        route.append(("binding", kwargs.get("require_host", False)))
        return actual_binding(event, operation, **kwargs)

    def deny_action(path, event, combat_id):
        assert checks == [True] and len(verifications) == 1
        denied.append(path)
        return None  # Admission-only test; no mutation is performed.

    monkeypatch.setattr(ctx.combat, "_require_current_response_event", current)
    monkeypatch.setattr(ctx.combat, "_practice_mutation", binding)
    monkeypatch.setattr(ctx.combat, "_quarantine_file", deny_action)
    monkeypatch.setattr(ctx.combat, "_host_mutation_allowed", _forbidden)
    ctx.combat._handle(ctx.event)
    assert route == [("current", False), ("binding", True)]
    assert checks == [True] and denied == [str(ctx.marker)]
    assert ctx.marker.is_file()


def test_direct_handle_revoked_real_issuer_scope_cannot_fall_through_protect(source_canary, monkeypatch):
    ctx = source_canary
    checks, _verifications = _count_real_validation(monkeypatch)
    monkeypatch.setattr("angerona.core.breach_state.protect_authority", lambda: (True, "Inert host boundary"))
    monkeypatch.setattr(ctx.combat, "_quarantine_file", _forbidden)
    monkeypatch.setattr(ctx.combat, "_host_mutation_allowed", _forbidden)
    policy = purple.policy_path(ctx.root)
    original = policy.read_bytes()
    try:
        policy.write_bytes(original + b"\n")
        ctx.combat._handle(ctx.event)
        assert checks == [False]
        assert ctx.combat._host_authority_verified is False
    finally:
        policy.write_bytes(original)
    assert ctx.marker.is_file()


def test_direct_handle_bus_signed_bad_inner_receipt_is_held_under_protect(source_canary, monkeypatch):
    ctx = source_canary
    forged = replace(ctx.event, details={**ctx.event.details, "detector_receipt_mac": "0" * 64})
    forged = replace(forged, hmac_sig=ctx.recorder.authority.sign(forged))
    assert ctx.bus.verify(forged)
    checks, _verifications = _count_real_validation(monkeypatch)
    refusals = _trace_bad_inner_receipt_refusals(monkeypatch, checks)
    monkeypatch.setattr("angerona.core.breach_state.protect_authority", lambda: (True, "Inert host boundary"))
    monkeypatch.setattr(ctx.combat, "_quarantine_file", _forbidden)
    monkeypatch.setattr(ctx.combat, "_host_mutation_allowed", _forbidden)
    ctx.combat._handle(forged)
    assert refusals and all(result is False and seen == () for result, seen in refusals)
    assert checks == []  # Actual inner authentication refused before scope/Protect/native work.
    assert ctx.combat._host_authority_verified is False
    assert ctx.marker.is_file()


@pytest.mark.parametrize("change", ["policy", "generation", "expired", "stop"])
def test_direct_handle_rechecks_complete_boundary_after_real_proof(source_canary, monkeypatch, change):
    ctx = source_canary
    checks, _verifications = _count_real_validation(monkeypatch)
    actual_validation = ctx.combat._canary_mutation_valid
    original_policy, original_clock = ctx.combat.policy(), combat.time
    original_generation = ctx.combat.lifecycle_generation
    changed = []

    def validate_then_change(*args, **kwargs):
        result = actual_validation(*args, **kwargs)
        assert result is True and checks == [True]
        changed.append(change)
        if change == "policy":
            monkeypatch.setattr(ctx.combat, "policy", lambda: replace(original_policy, min_severity=Severity.CRITICAL))
        elif change == "generation":
            ctx.combat._lifecycle_generation = original_generation + 1
        elif change == "expired":
            class AfterProofClock:
                def time(self):
                    return ctx.event.ts + 31
                def __getattr__(self, name):
                    return getattr(original_clock, name)
            monkeypatch.setattr(combat, "time", AfterProofClock())
        else:
            ctx.combat.stop()
        return result

    monkeypatch.setattr(ctx.combat, "_canary_mutation_valid", validate_then_change)
    monkeypatch.setattr(ctx.combat, "_quarantine_file", _forbidden)
    monkeypatch.setattr(ctx.combat, "_host_mutation_allowed", _forbidden)
    try:
        ctx.combat._handle(ctx.event)
        assert changed == [change] and checks == [True]
    finally:
        if change == "generation":
            ctx.combat._lifecycle_generation = original_generation
    assert ctx.marker.is_file()
