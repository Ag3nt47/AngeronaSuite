"""Actual current-member retirement algorithms under a local kernel API model.

No process token is forwarded to Windows and no scanner/Ollama is started.
The unchanged native-OS cells in test_ollama_owned_retirement separately verify
actual retained kernel signal0/Job0/unrelated-Job exclusion. Stable historical
TotalProcesses is deliberately allowed; this is not an all-history proof.
"""
from __future__ import annotations

from dataclasses import replace
import os
import subprocess

import pytest

from angerona.core import ollama_lifecycle as ollama
from angerona.core import windows_child_job as jobs
from angerona.core.windows_process_lease import ProcessLeaseError
from test_ollama_owned_retirement import (
    inert_child_factory as inert_child_factory, owned as owned,
)


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows native adapter contract model")


def prepare(owned, pids=(7001, 7002)):
    sample = owned.make(pids, register=False)
    sample.owner.prepare_tree_retirement(timeout=1.0)
    return sample, sample.owner._tree_retirement


def assert_lifetime_held(sample):
    assert sample.owner._process is sample.root and sample.job._handle is sample.job_lifetime
    assert not sample.root.closed and not sample.job_lifetime.closed
    assert sample.owner.tree_retirement_snapshot()["handles_closed"] is False


def test_job_zero_cannot_replace_captured_runner_signal_and_retry_uses_exact_capsule(owned):
    sample = owned.make()
    runner = sample.members[0][1]
    owned.transport.stubborn.add(runner)
    outcome = ollama.stop_owned_ollama_services(timeout=0.1)
    capsule = sample.owner._tree_retirement
    handles = tuple(capsule.handles)
    assert sample.model.retirement_dispatched and owned.kernel.current(sample.model) == ()
    assert runner not in owned.native.exited  # Model actual Job0 and unsignaled handle separately.
    assert outcome["state"] == "incomplete" and outcome["complete"] is False
    assert ollama._owned_services[sample.key] is sample.owner
    row, = outcome["records"]
    assert row["service_exited"] and not row["job_empty"] and not row["handles_closed"]
    assert row["error_type"] == "TimeoutExpired"
    assert row["current_job_signal_proof"]["signals_proven"] is False
    assert not any(label == "close" for label, _process, _job in sample.lifecycle_calls)
    assert_lifetime_held(sample)
    owned.native.exited.add(runner)
    owned.transport.stubborn.clear()
    result = ollama.stop_owned_ollama_services(timeout=1.0)
    assert result["complete"] is True and result["pending_owned"] == 0
    assert sample.owner._tree_retirement is capsule
    assert set(handles).issubset(owned.native.closed)
    assert all(owned.native.closed.count(handle) == 1 for handle in handles)
    assert sample.root.closes == sample.job_lifetime.closes == 1
    assert sample.key not in ollama._owned_services


@pytest.mark.parametrize("root_exited,all_exited", [(False, False), (True, False), (True, True)])
def test_current_cut_accepts_stable_historical_total_and_retained_exited_root(owned, root_exited, all_exited):
    sample = owned.make(register=False)
    sample.model.retirement_total = 17  # Legitimate historical exits are not cold-roster mismatches.
    if root_exited:
        owned.native.exited.add(sample.owner.pid)
    if all_exited:
        owned.native.exited.update(sample.members[0])
    sample.owner.prepare_tree_retirement(timeout=1.0)
    capsule = sample.owner._tree_retirement
    expected_captured = 1 if all_exited else 2
    assert len(capsule.processes) == expected_captured
    assert capsule.total == 17 and capsule.ready
    assert sample.owner.pid not in [pid for pid, *_rest in owned.native.opened]
    sample.owner.terminate()
    sample.owner.wait(timeout=0.2)
    sample.owner.wait_tree(timeout=0.2)
    sample.owner.close()
    snapshot = sample.owner.tree_retirement_snapshot()
    assert snapshot["captured_processes"] == expected_captured
    assert snapshot["total_processes_at_cut"] == 17
    assert snapshot["signals_proven"] and snapshot["handles_closed"]
    assert "historical exits not collected" in snapshot["scope"]
    assert sample.root.closes == sample.job_lifetime.closes == 1


def test_live_root_absent_from_complete_current_list_is_held_but_exact_stop_is_attempted(owned):
    sample = owned.make()
    sample.members[:] = [[]]
    outcome = ollama.stop_owned_ollama_services(timeout=0.2)
    assert sample.model.termination_calls == [1]
    assert outcome["complete"] is False and outcome["pending_owned"] == 1
    assert sample.owner.tree_retirement_snapshot()["cut_ready"] is False
    assert ollama._owned_services[sample.key] is sample.owner
    assert_lifetime_held(sample)


@pytest.mark.parametrize("change", ["counter-before-dispatch", "counter-after-dispatch", "new-roster-after-dispatch"])
def test_post_cut_accounting_or_membership_change_never_becomes_completion(owned, change):
    sample, capsule = prepare(owned)
    captured = tuple(capsule.processes)
    if change == "counter-before-dispatch":
        sample.model.retirement_total += 1
    sample.owner.terminate()
    assert sample.model.termination_calls == [1]
    if change == "counter-after-dispatch":
        sample.model.retirement_total += 1  # Includes an unseen spawn+exit even with an empty current list.
    elif change == "new-roster-after-dispatch":
        sample.model.retirement_roster = (7999,)
    before_clock = owned.clock[0]
    with pytest.raises(jobs.NativeOwnershipObservationError):
        sample.owner.wait_tree(timeout=0.2)
    assert owned.clock[0] == before_clock, "A changed high-water/roster must not be retried into a fresh cut"
    assert sample.owner._tree_retirement is capsule and tuple(capsule.processes) == captured
    assert not any(pid == 7999 for pid, *_rest in owned.native.opened)
    assert_lifetime_held(sample)
    with pytest.raises(jobs.NativeOwnershipObservationError):
        sample.owner.close()
    assert_lifetime_held(sample)


def test_capture_roster_race_keeps_all_opened_queries_and_does_not_refresh_cut(owned):
    sample = owned.make()
    count = [0]

    def race(operation, subject):
        if operation == "members" and subject == sample.model.token:
            count[0] += 1
            if count[0] == 2:
                sample.members[:] = [[sample.owner.pid, 7999]]

    owned.native.hook = race
    with pytest.raises(jobs.NativeOwnershipObservationError, match="cut changed"):
        sample.owner.prepare_tree_retirement(timeout=1.0)
    capsule = sample.owner._tree_retirement
    assert capsule.handles and not capsule.ready and capsule.failure
    assert not owned.native.closed
    owned.native.hook = None
    sample.owner.terminate()
    assert sample.model.termination_calls == [1]
    with pytest.raises(jobs.NativeOwnershipObservationError, match="custody is held"):
        sample.owner.prepare_tree_retirement(timeout=1.0)
    assert sample.owner._tree_retirement is capsule
    assert_lifetime_held(sample)


@pytest.mark.parametrize("total,active", [(0, 2), (1, 2), (2, 17)])
def test_native_accounting_inconsistency_holds_without_close_or_history_inference(owned, total, active):
    sample = owned.make(register=False)
    sample.model.retirement_total, sample.model.retirement_active_override = total, active
    with pytest.raises(jobs.NativeOwnershipObservationError, match="accounting"):
        sample.owner.prepare_tree_retirement(timeout=1.0)
    sample.owner.terminate()
    assert sample.model.termination_calls == [1]
    assert sample.owner.tree_retirement_snapshot()["cut_ready"] is False
    assert_lifetime_held(sample)


@pytest.mark.parametrize("change", ["partial-list", "foreign-member", "changed-birth"])
def test_incomplete_list_membership_or_native_birth_refuses_complete_cut(owned, change):
    sample = owned.make(register=False)
    runner = sample.members[0][1]
    if change == "partial-list":
        sample.model.assigned, sample.model.count = 3, 2
    elif change == "foreign-member":
        owned.native.nonmembers.add(runner)
    else:
        seen = [0]

        def changed_birth(operation, subject):
            if operation == "object-birth" and subject == runner:
                seen[0] += 1
                if seen[0] == 2:
                    prior = owned.native.identities[runner]
                    owned.native.identities[runner] = replace(prior, birth_ticks=prior.birth_ticks + 1)

        owned.native.hook = changed_birth
    with pytest.raises(jobs.NativeOwnershipObservationError):
        sample.owner.prepare_tree_retirement(timeout=1.0)
    assert sample.owner.tree_retirement_snapshot()["cut_ready"] is False
    assert_lifetime_held(sample)


def test_native_birth_change_after_exit_is_rejected_without_image_requery(owned):
    sample, capsule = prepare(owned)
    runner = sample.members[0][1]
    sample.owner.terminate()
    before = owned.native.identities[runner]
    owned.native.identities[runner] = replace(before, birth_ticks=before.birth_ticks + 1)
    image_queries = [event for event in owned.native.calls if event[0] == "identity"]
    with pytest.raises(jobs.NativeOwnershipObservationError, match="generation"):
        sample.owner.wait_tree(timeout=0.2)
    assert [event for event in owned.native.calls if event[0] == "identity"] == image_queries
    assert capsule.waited is False
    assert_lifetime_held(sample)


def test_prepare_native_query_failure_still_dispatches_exact_existing_job(owned):
    sample = owned.make()
    owned.native.fail[("retirement-accounting", sample.model.token)] = OSError("inert native accounting failure")
    result = ollama.stop_owned_ollama_services(timeout=0.2)
    assert sample.model.termination_calls == [1]
    assert result["complete"] is False and result["pending_owned"] == 1
    assert ollama._owned_services[sample.key] is sample.owner
    assert result["records"][0]["current_job_signal_proof"]["cut_ready"] is False
    assert_lifetime_held(sample)


def test_all_captured_waits_share_one_remaining_deadline(owned):
    sample = owned.make((7001, 7002, 7003), register=False)
    first, second = sample.members[0][1:]
    start = owned.clock[0]
    sample.model.retirement_signal_at = {first: start + 0.025, second: start + 0.15}
    sample.owner.prepare_tree_retirement(timeout=1.0)
    sample.owner.terminate()
    with pytest.raises(subprocess.TimeoutExpired):
        sample.owner.wait_tree(timeout=0.1)
    waits = [row for row in owned.kernel.waits if row[1] in (first, second) and row[2] > 0]
    assert [row[1] for row in waits] == [first, second]
    assert 0 < waits[1][2] < waits[0][2] <= 100
    assert owned.clock[0] <= start + 0.101
    assert first in owned.native.exited and second not in owned.native.exited
    assert_lifetime_held(sample)


def test_private_wait_entry_delay_cannot_renew_outer_deadline(owned, monkeypatch):
    sample, capsule = prepare(owned)
    sample.owner.terminate()
    actual_wait = jobs._OwnedTreeRetirement.wait

    def delayed(current, *args, **kwargs):
        assert current is capsule
        owned.clock[0] += 0.2
        return actual_wait(current, *args, **kwargs)

    monkeypatch.setattr(jobs._OwnedTreeRetirement, "wait", delayed)
    before = list(owned.native.calls)
    with pytest.raises(subprocess.TimeoutExpired):
        sample.owner.wait_tree(timeout=0.1)
    assert owned.native.calls == before, "Expired private entry must refuse before any new native query"
    assert capsule.waited is False
    assert_lifetime_held(sample)


def test_job_accounting_may_settle_only_inside_original_budget_after_signal_proof(owned):
    sample, capsule = prepare(owned)
    sample.owner.terminate()
    after_dispatch = [0]

    def settle(operation, subject):
        if operation == "retirement-accounting" and subject == sample.model.token:
            after_dispatch[0] += 1
            sample.model.retirement_active_override = 1 if after_dispatch[0] <= 2 else None

    owned.native.hook = settle
    start = owned.clock[0]
    sample.owner.wait_tree(timeout=0.1)
    assert 0.01 <= owned.clock[0] - start <= 0.03
    assert capsule.waited and after_dispatch[0] >= 3
    owned.native.hook = None
    sample.owner.close()
    assert sample.owner.tree_retirement_snapshot()["handles_closed"] is True


def test_failed_native_wait_is_not_a_signal_or_a_reason_to_close(owned):
    sample, capsule = prepare(owned)
    runner = sample.members[0][1]
    sample.owner.terminate()
    sample.model.retirement_wait_codes[runner] = 0xffffffff
    with pytest.raises(ProcessLeaseError, match="WaitForSingleObject"):
        sample.owner.wait_tree(timeout=0.2)
    assert capsule.waited is False
    assert_lifetime_held(sample)


def test_raw_query_close_lost_ack_is_sticky_and_never_retried_on_closed_values(owned):
    sample, capsule = prepare(owned)
    sample.owner.terminate()
    sample.owner.wait_tree(timeout=0.2)
    attempted = []

    def lost_ack(operation, subject):
        if operation == "close" and not attempted:
            attempted.append(subject)  # Inert kernel close already happened before this acknowledgement fault.
            raise OSError("inert query close acknowledgement lost")

    owned.native.hook = lost_ack
    with pytest.raises(jobs.NativeOwnershipObservationError, match="close remains unproven"):
        sample.owner.close()
    snapshot = sample.owner.tree_retirement_snapshot()
    assert snapshot["signals_proven"] and snapshot["close_held"] and not snapshot["handles_closed"]
    assert len(attempted) == 1 and owned.native.closed.count(attempted[0]) == 1
    assert_lifetime_held(sample)
    before = list(owned.native.closed), list(owned.native.calls)
    for action in (sample.owner.close, lambda: sample.owner.prepare_tree_retirement(timeout=1.0)):
        with pytest.raises(jobs.NativeOwnershipObservationError):
            action()
    assert (owned.native.closed, owned.native.calls) == before
    assert capsule in jobs._OWNED_TREE_RETIREMENTS
    assert any(owner is sample.owner and handle == attempted[0]
               for owner, _native, handle in jobs._OWNED_OBSERVATION_CLOSE_HOLDS)


def test_detached_summary_cannot_bypass_signal_proof_or_replace_exact_owner(owned):
    sample, capsule = prepare(owned)
    row = sample.owner.tree_retirement_snapshot()
    row["signals_proven"], row["handles_closed"] = True, True
    with pytest.raises(jobs.NativeOwnershipObservationError):
        sample.owner.close()
    assert capsule.waited is False and capsule.closed is False
    # Dispatch the real prepared cut first; an undispatched cut is correctly
    # refused before owner validation and cannot exercise this generation gate.
    sample.owner.terminate()
    assert capsule.ready and capsule.dispatched and not capsule.waited
    replacement = owned.native.lifetime("process", sample.owner.pid)
    sample.owner._process = replacement
    before = list(owned.native.calls)
    with pytest.raises(jobs.NativeOwnershipObservationError, match="lifetime changed"):
        sample.owner.wait_tree(timeout=0.2)
    assert owned.native.calls == before
    assert not sample.job_lifetime.closed and not sample.root.closed and not replacement.closed


def test_generic_live_observer_keeps_its_original_nonempty_root_contract(owned):
    sample = owned.make(register=False)
    owned.native.exited.update(sample.members[0])
    assert sample.owner.tree_retirement_snapshot() is None
    with pytest.raises(jobs.NativeOwnershipObservationError):
        sample.owner.observe_owned_process_identities(timeout=1.0)
    assert sample.owner.tree_retirement_snapshot() is None
    assert not sample.job_lifetime.closed and not sample.root.closed


def test_bound_adapter_leaves_other_actual_composed_jobs_in_original_live_domain(owned, inert_child_factory):
    ai = owned.make(register=False)
    companion = inert_child_factory((8101, 8102))  # Same native fixture, deliberately not bound to the AI adapter.
    assert id(companion.model) not in owned.kernel.bound_models
    before = len(owned.native.opened)
    rows = companion.owner.observe_owned_process_identities(role="other-component", timeout=1.0)
    assert {row.pid for row in rows} == {8101, 8102}
    assert len(owned.native.opened) == before + 1
    assert companion.owner.tree_retirement_snapshot() is None
    assert not companion.root.closed and not companion.job._handle.closed
    ai.owner.prepare_tree_retirement(timeout=1.0)
    ai.owner.terminate()
    ai.owner.wait_tree(timeout=0.2)
    ai.owner.close()
    assert not companion.root.closed and not companion.job._handle.closed


def test_returned_nested_signal_proof_cannot_mutate_retained_retirement_publication(owned):
    sample = owned.make()
    outcome = ollama.stop_owned_ollama_services(timeout=1.0)
    assert outcome["complete"] is True and sample.key not in ollama._owned_services
    assert sample.root.closes == sample.job_lifetime.closes == 1
    first = ollama.ollama_retirement_snapshot()
    proof = first["records"][0]["current_job_signal_proof"]
    assert proof["signals_proven"] is True and proof["handles_closed"] is True
    assert proof["captured_processes"] == 2 and proof["total_processes_at_cut"] == 2
    expected = dict(proof)
    proof["signals_proven"] = False
    proof["handles_closed"] = False
    proof["captured_processes"] = 0
    proof["scope"] = "caller-mutated diagnostic copy"
    second = ollama.ollama_retirement_snapshot()
    retained = second["records"][0]["current_job_signal_proof"]
    assert retained == expected and retained is not proof
    assert outcome["records"][0]["current_job_signal_proof"] == expected
    assert sample.owner.tree_retirement_snapshot() == expected
    assert sample.key not in ollama._owned_services
    assert sample.root.closes == sample.job_lifetime.closes == 1
