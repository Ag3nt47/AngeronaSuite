"""Exercise initial canary admission in the actual termination transaction.

No process is launched or killed. The existing admission fixture represents
upstream cryptographic issuer verification; the native API and durable journal
are explicit inert seams. Production transaction ordering, exact owned roster,
Bridge probe registry, canary/Job/plan checks and WindowsProcessLease stay real.
This verifies ordering and fail-closed behavior, not host response efficacy.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace

import pytest
from test_red_team_standalone_admission import admission  # noqa: F401

from angerona.core import breach_state, windows_process_lease as lease_module
from angerona.core.response_contract import authorize_response
from angerona.modules import adversary_combat as combat_module
from angerona.modules.adversary_combat import HostMutationHeld, _CanaryMutation


@pytest.fixture
def transaction(admission, monkeypatch):
    sample = admission
    module = sample.combat
    calls = []
    native_state = {"alive": True, "opened": False, "closed": False, "effects": 0}
    upstream = {"valid": True}
    guards = []
    policy = combat_module.CombatPolicy(mode="maximum", process_action="terminate",
                                       block_network=False)
    sample.canary.event.details.update({
        "pid": sample.identity.pid,
        "process_create_time": sample.identity.create_time,
        **authorize_response(["terminate_process"], pid=sample.identity.pid,
                             process_create_time=sample.identity.create_time),
    })
    # Existing issuer/HMAC verification is modeled, never granted by these test
    # inputs. The production registry/roster/native target checks remain real.
    def issuer_verified(proof, **_kwargs):
        return type(proof) is _CanaryMutation and upstream["valid"]

    def original_event(event, *, canary=None, **_kwargs):
        if (event is not sample.canary.event or not issuer_verified(canary)
                or module.stopping):
            raise HostMutationHeld("Inert original issuer proof is unavailable.")

    monkeypatch.setattr(module, "_canary_mutation_valid", issuer_verified)
    monkeypatch.setattr(breach_state, "protect_authority", lambda: (False, "inert Source Observe"))
    monkeypatch.setattr(breach_state, "verified_breach", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "_require_current_response_event", original_event)
    monkeypatch.setattr(module, "_integrity_ok", lambda event: event is sample.canary.event)
    monkeypatch.setattr(module, "policy", lambda: policy)
    monkeypatch.setattr(module, "_is_system_path", lambda _path: False)
    monkeypatch.setattr(combat_module, "time", SimpleNamespace(
        monotonic=lambda: sample.clock[0], time=lambda: sample.canary.event.ts))

    class InertNative:
        def open(self, pid, rights, inherit):
            assert (pid, rights, inherit) == (sample.identity.pid, lease_module._RIGHTS, False)
            assert not native_state["opened"] and not native_state["closed"]
            native_state["opened"] = True
            calls.append("open")
            return 101

        def identity(self, handle):
            assert handle == 101 and native_state["alive"] and not native_state["closed"]
            calls.append("identity")
            return sample.identity

        def object_identity(self, handle):
            assert handle == 101 and not native_state["alive"] and not native_state["closed"]
            calls.append("object-identity")
            return sample.identity.pid, sample.identity.birth_ticks

        def wait(self, handle, milliseconds):
            assert handle == 101 and not native_state["closed"]
            assert type(milliseconds) is int and 0 <= milliseconds <= 3000
            calls.append("wait" if milliseconds else "poll")
            return not native_state["alive"]

        def terminate(self, handle, code):
            assert (handle, code) == (101, 1)
            assert native_state["alive"] and not native_state["closed"]
            custody = module._response_dispatch_local.process_custody
            assert type(custody.lease) is lease_module.WindowsProcessLease
            assert custody.lease.identity is sample.identity
            assert custody.lease.dispatch_started is True
            assert "intent" in calls
            native_state["effects"] += 1
            native_state["alive"] = False
            calls.append("terminate")

        def exit_code(self, handle):
            assert handle == 101 and not native_state["alive"] and not native_state["closed"]
            calls.append("exit-code")
            return 1

        def close(self, handle):
            assert handle == 101 and native_state["opened"] and not native_state["closed"]
            native_state["closed"] = True
            calls.append("close")

    native = InertNative()
    factories = []
    def native_factory():
        factories.append(True)
        assert len(factories) == 1, "the transaction must retain one native process object"
        return native

    monkeypatch.setattr(combat_module, "_WINDOWS_PROCESS_CUSTODY", True)
    monkeypatch.setattr(lease_module, "_Native", native_factory)
    sample.process.kill = lambda: pytest.fail("PID-based termination fallback was used")
    original_guard = module._require_not_owned_identity
    def record_real_guard(identity, *, canary=None, action=None):
        guards.append({"before_intent": "intent" not in calls,
                       "dispatch": getattr(module._response_dispatch_local, "context", None)})
        calls.append("owned-guard")
        return original_guard(identity, canary=canary, action=action)
    monkeypatch.setattr(module, "_require_not_owned_identity", record_real_guard)

    @contextmanager
    def journal(action, *, event, canary=None):
        # This is the production order: the first native ownership admission
        # occurs BEFORE intent and BEFORE this thread-local context exists.
        assert guards and guards[0] == {"before_intent": True, "dispatch": None}
        assert event is sample.canary.event
        module._require_host_mutation_authority(canary=canary, action=action)
        calls.append("intent")
        previous = getattr(module._response_dispatch_local, "context", None)
        module._response_dispatch_local.context = (event, canary, action, None)
        try:
            module._require_host_mutation_authority(canary=canary, action=action)
            yield
        finally:
            module._response_dispatch_local.context = previous

    terminal_proofs = []
    def commit(action):
        validator = module._terminal_commit_local.validator
        assert callable(validator)
        proof = validator()
        assert proof["native_pid"] == sample.identity.pid
        assert proof["native_birth_ticks"] == sample.identity.birth_ticks
        assert proof["native_image"] == sample.identity.image
        assert proof["native_wait_signaled"] is True
        assert proof["native_exit_code"] == 1
        terminal_proofs.append(proof)
        calls.append("commit")
        return replace(action, details={**action.details, **proof, "postcondition_verified": True})

    failures = []
    monkeypatch.setattr(module, "_journaled_mutation", journal)
    monkeypatch.setattr(module, "_commit_after_mutation", commit)
    monkeypatch.setattr(module, "_journal_failure", lambda *_args: failures.append(True))
    monkeypatch.setattr(module, "_mark_nonreversible_uncertain",
                        lambda *_args: pytest.fail("inert pre-effect refusal became an effect"))
    return SimpleNamespace(sample=sample, module=module, policy=policy, native=native,
        native_state=native_state, calls=calls, guards=guards, factories=factories,
        terminal_proofs=terminal_proofs, failures=failures, upstream=upstream)


def run_transaction(tx, canary):
    return tx.module._terminate_process_transaction(
        tx.sample.process, tx.sample.action, event=tx.sample.canary.event,
        expected_policy=tx.policy, canary=canary)


def test_exact_enrolled_probe_reaches_effect_before_any_journal_tls_exists(transaction):
    tx = transaction
    result = run_transaction(tx, tx.sample.canary)
    assert result is not None and result.status == "applied"
    assert tx.guards[0] == {"before_intent": True, "dispatch": None}
    assert tx.calls.index("owned-guard") < tx.calls.index("intent") < tx.calls.index("terminate")
    assert tx.calls.index("terminate") < tx.calls.index("commit") < tx.calls.index("close")
    assert len(tx.guards) >= 5, "later production ownership barriers must also run"
    assert tx.native_state == {"alive": False, "opened": True, "closed": True, "effects": 1}
    assert len(tx.terminal_proofs) == 1 and tx.factories == [True]
    assert tx.failures == []
    assert getattr(tx.module._response_dispatch_local, "context", None) is None


@pytest.mark.parametrize("failure", [
    "absent", "forged", "wrong-token", "wrong-run", "wrong-lease", "released-lease",
    "wrong-plan", "wrong-step", "cancelled", "other-job", "closed-job", "closed-pin",
    "wrong-parent", "wrong-command", "wrong-image", "wrong-birth", "other-role",
    "expired-roster", "supplier-unavailable", "stale-issuer", "stopped",
])
def test_ambiguous_or_stale_canary_never_reaches_intent_or_effect(transaction, failure):
    tx, sample = transaction, transaction.sample
    proof = sample.canary
    if failure == "absent":
        proof = None
    elif failure == "forged":
        proof = SimpleNamespace(**proof.__dict__)
    elif failure == "wrong-token":
        proof.event.details["correlation_token"] = "ANGERONA_REDTEAM_ffffffff"
    elif failure == "wrong-run":
        proof.event.details["run_id"] = "redteam-" + "f" * 32
    elif failure == "wrong-lease":
        proof = replace(proof, lease=object())
    elif failure == "released-lease":
        sample.state.released = True
    elif failure == "wrong-plan":
        sample.engine._prepared_run = SimpleNamespace(plan_sha256="e" * 64)
    elif failure == "wrong-step":
        sample.engine._active_plan_entry = {"key": "other", "plan_step_id": "different"}
    elif failure == "cancelled":
        sample.engine._cancel.set()
    elif failure == "other-job":
        sample.job.member = False
    elif failure == "closed-job":
        sample.job.closed = True
    elif failure == "closed-pin":
        sample.pin.closed = True
    elif failure == "wrong-parent":
        sample.process.ppid = lambda: 9999
    elif failure == "wrong-command":
        sample.command[-1] = "ANGERONA_REDTEAM_ffffffff"
    elif failure == "wrong-image":
        sample.process.exe = lambda: "C:/other/python.exe"
    elif failure == "wrong-birth":
        sample.owner._probes[sample.record.probe_id] = replace(
            sample.record, identity=replace(sample.identity, birth_ticks=sample.identity.birth_ticks + 1))
    elif failure == "other-role":
        sample.manager.owned_process_identities = lambda: tuple(
            replace(row, role="scanner") if row.pid == sample.identity.pid else row
            for row in sample.rows)
    elif failure == "expired-roster":
        sample.clock[0] = 102.0
    elif failure == "supplier-unavailable":
        def unavailable():
            raise RuntimeError("inert owned-roster supplier unavailable")
        sample.manager.owned_process_identities = unavailable
    elif failure == "stale-issuer":
        tx.upstream["valid"] = False
    else:
        tx.module._stop.set()
    assert run_transaction(tx, proof) is None
    assert "intent" not in tx.calls and "terminate" not in tx.calls and "commit" not in tx.calls
    assert tx.native_state["alive"] and tx.native_state["effects"] == 0
    assert tx.native_state["closed"] is tx.native_state["opened"]


def test_ambient_journal_context_cannot_authorize_missing_explicit_initial_proof(transaction):
    tx, sample = transaction, transaction.sample
    tx.module._response_dispatch_local.context = (sample.canary.event, sample.canary, sample.action, None)
    returned_lease = None
    try:
        with pytest.raises(HostMutationHeld):
            returned_lease = tx.module._acquire_termination_lease(sample.action)
    finally:
        tx.module._response_dispatch_local.context = None
        if returned_lease is not None:
            returned_lease.close()
    assert tx.native_state["opened"] and tx.native_state["closed"]
    assert tx.native_state["alive"] and tx.native_state["effects"] == 0
    assert "intent" not in tx.calls and "terminate" not in tx.calls


def test_stop_after_initial_admission_still_prevents_intent_and_effect(transaction, monkeypatch):
    tx, sample = transaction, transaction.sample
    guard = tx.module._require_not_owned_identity
    def stop_after_first(identity, **kwargs):
        result = guard(identity, **kwargs)
        if len(tx.guards) == 1:
            tx.module._stop.set()
        return result
    monkeypatch.setattr(tx.module, "_require_not_owned_identity", stop_after_first)
    assert run_transaction(tx, sample.canary) is None
    assert tx.guards and tx.guards[0]["dispatch"] is None
    assert "intent" not in tx.calls and "terminate" not in tx.calls
    assert tx.native_state == {"alive": True, "opened": True, "closed": True, "effects": 0}
