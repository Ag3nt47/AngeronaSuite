"""Avoid duplicate scope work without skipping current issuer/native guards."""
from __future__ import annotations

from dataclasses import replace
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
            altered = replace(proof.event, details={
                **proof.event.details, "detector_receipt_mac": "0" * 64,
            })
            altered = replace(altered, hmac_sig=ctx.recorder.authority.sign(altered))
            assert ctx.bus.verify(altered), "Reach the inner issuer HMAC boundary"
            forged = replace(proof, event=altered, signature=altered.hmac_sig)
            assert not ctx.combat._canary_mutation_valid(forged, pinned=pinned)
            assert checks == [True] * 4
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
