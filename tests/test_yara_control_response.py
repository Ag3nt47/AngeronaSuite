"""Control claims keep narrow custody; completed effects retain truthful receipts.

Ordinary receipt streaming remains bounded and available independently of the
optional control plane. Actual rollback faults must restore the same object.
"""
from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest
import yara_x

from angerona.core.response_proof import event_proof_digest
from angerona.core.practice_scope import register_artifact
from angerona.core import breach_state
from angerona.core.eventbus import BusAuthority, EventBus
from angerona.modules import purple_guard, yara_scanner
from angerona.modules.yara_scanner import YaraScannerModule
from test_yara_automatic_response import (
    MARKER, _CountedNativeScanner, _wait_for,
)
from test_yara_automatic_response import controlled_runtime  # noqa: F401


def test_every_ordinary_detection_is_verifiable_inline_beyond_receipt_capacity(tmp_path):
    """Exercise receipt scheduling, not native efficacy or host response."""
    bus = EventBus(ring_size=1)
    bus.arm(BusAuthority(b"b" * 32))
    detector = YaraScannerModule()
    detector.bind(bus)
    path = tmp_path / "ordinary-capacity.txt"
    path.write_bytes(b"inert ordinary capacity fixture")
    rule_names = tuple(f"OrdinaryCapacity_{index}" for index in range(4097))

    class OrdinaryScannerFixture:
        def scan(self, _content):
            return SimpleNamespace(matching_rules=tuple(
                SimpleNamespace(identifier=name) for name in rule_names))

    delivered = []
    invalid = []

    def verify_inline(event):
        authenticated = bus.verify(event)
        current = detector.verify_detection_event(event)
        bounded = len(detector._detection_receipts) <= 4096
        delivered.append(event.details["rule"])
        if not (authenticated and current and bounded):
            invalid.append((event.details["rule"], authenticated, current, bounded))
        # EventBus isolates callback exceptions. The final invalid assertion
        # also makes any swallowed callback assertion fail this test.
        assert authenticated and current and bounded

    bus.subscribe(verify_inline)
    try:
        assert detector._scan_file(OrdinaryScannerFixture(), path) == "scanned", detector.last_error
    finally:
        bus.unsubscribe(verify_inline)
    assert delivered == list(rule_names)
    assert not invalid
    assert len(bus.recent(2)) == 1
    assert len(detector._detection_receipts) == 4096


def _capture_sealed_without_attempt(ctx, kind="text"):
    # Actual native observation remains real. Common response policy withholds
    # the queued original until it is drained; it is never manually dispatched.
    ctx.config.adversary_combat_quarantine_files = False
    declaration, path, original = ctx.create_control(kind)
    ctx.begin_scan()
    event = _wait_for(lambda: ctx.detection(path), description="real control scan did not publish")
    assert ctx.bus.verify(event) and ctx.detector.verify_detection_event(event)
    assert ctx.detector.verify_control_detection_event(event)
    ctx.drain()
    assert path.read_bytes() == original
    assert not ctx.combat.list_actions()
    assert not purple_guard.verify_yara_control_event(ctx.lease, ctx.combat, event)
    ctx.config.adversary_combat_quarantine_files = True
    assert purple_guard.verify_yara_control_event(ctx.lease, ctx.combat, event)
    return declaration, path, original, event


def test_bare_practice_registration_cannot_borrow_genuine_control_factory(controlled_runtime):
    ctx = controlled_runtime
    path = ctx.target / "bare-registry.txt"
    path.write_bytes(MARKER)
    assert register_artifact(path, ctx.run_id, kind="shark")
    ctx.begin_scan()
    event = _wait_for(lambda: ctx.detection(path), description="real native bare-registry scan did not publish")
    ctx.drain()
    assert ctx.bus.verify(event) and ctx.detector.verify_detection_event(event)
    assert not event.details.get("yara_control_claim_id")
    assert not ctx.detector.verify_control_detection_event(event)
    assert not purple_guard.verify_yara_control_event(ctx.lease, ctx.combat, event)
    assert path.read_bytes() == MARKER and not ctx.combat.list_actions()
    assert ctx.combat.response_snapshot()["host_authority_verified"] is False


@pytest.mark.parametrize("control_unavailable", [False, True])
def test_ordinary_native_detection_continues_with_live_or_unavailable_control_factory(
    controlled_runtime, monkeypatch, control_unavailable,
):
    ctx = controlled_runtime
    if control_unavailable:
        monkeypatch.setattr(yara_scanner, "distribution_version", lambda _name: "0.unvalidated")
        capability = ctx.detector._redteam_receipt_capability
        ctx.detector.bind_redteam_receipt_capability(capability, expected=capability)
    path = ctx.target / "ordinary-unregistered-notes.txt"
    path.write_bytes(MARKER)
    ctx.begin_scan()
    event = _wait_for(lambda: ctx.detection(path), description="ordinary native scanner stopped behind control setup")
    ctx.drain()
    assert ctx.bus.verify(event) and ctx.detector.verify_detection_event(event)
    assert event.details["observed_content_sha256"] == hashlib.sha256(MARKER).hexdigest()
    assert event.details["response_authorized"] is False
    assert not event.details.get("yara_control_claim_id")
    assert not ctx.detector.verify_control_detection_event(event)
    if control_unavailable:
        _wait_for(lambda: ctx.detector._control_last_error,
                  description="held control factory did not expose its diagnostic")
        assert "version" in ctx.detector._control_last_error.lower()
        assert ctx.detector.control_enrollment() is None
        assert any(row.details.get("control_validation_reason")
                   for row in ctx.captured() if row.module == ctx.detector.name)
    else:
        assert ctx.detector.control_enrollment() is not None
    assert path.read_bytes() == MARKER and not ctx.combat.list_actions()
    assert ctx.combat.response_snapshot()["host_authority_verified"] is False


def test_forwarding_native_scanner_cannot_issue_control_claim(controlled_runtime):
    ctx = controlled_runtime
    _declaration, path, original = ctx.create_control("text")
    rules = scanner = forwarded = None
    try:
        rules = yara_x.compile(
            'rule EICAR_Test_File { strings: $m="EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: $m }')
        scanner = ctx.detector._make_scanner(rules)
        forwarded = _CountedNativeScanner(scanner)
        assert ctx.detector._scan_file(forwarded, path) == "scanned", ctx.detector.last_error
        event = _wait_for(lambda: ctx.detection(path), description="native forwarding observation was not emitted")
        ctx.drain()
        assert forwarded.calls == 1
        assert ctx.bus.verify(event) and ctx.detector.verify_detection_event(event)
        assert not event.details.get("yara_control_claim_id")
        assert not ctx.detector.verify_control_detection_event(event)
        assert not purple_guard.verify_yara_control_event(ctx.lease, ctx.combat, event)
        assert path.read_bytes() == original and not ctx.combat.list_actions()
    finally:
        # These raw native objects were created on this test thread and remain
        # here. The genuine worker owns a separate control scanner throughout.
        forwarded = scanner = rules = None


def test_direct_capability_call_outside_scan_site_cannot_reserve_claim(controlled_runtime):
    ctx = controlled_runtime
    declaration, path, original = ctx.create_control("text")
    capability = ctx.detector._redteam_receipt_capability
    assert capability is not None
    reservation = capability.reserve_yara_observation(
        ctx.detector, enrollment=ctx.detector.control_enrollment(), path=str(path),
        rule=declaration["rule"], archive_member="", scan_serial=1,
        observed_content_sha256=hashlib.sha256(original).hexdigest(),
        observed_file_identity=declaration["identity"], scan_complete=True)
    assert reservation is None
    assert path.read_bytes() == original and not ctx.combat.list_actions()


@pytest.mark.parametrize("field", ["rule", "archive_member", "observed_content_sha256", "yara_control_recipe_sha256"])
def test_resigned_control_payload_cannot_reuse_opaque_claim(controlled_runtime, field):
    ctx = controlled_runtime
    _declaration, path, original, event = _capture_sealed_without_attempt(ctx)
    changed = copy.deepcopy(event.details)
    changed[field] = "0" * 64 if field.endswith("sha256") else "different-native-evidence"
    ctx.bus.publish(replace(event, details=changed))
    forged = next(row for row in reversed(ctx.captured())
                  if row.module == event.module and row.details.get(field) == changed[field])
    ctx.drain()
    assert ctx.bus.verify(forged)
    assert not ctx.detector.verify_control_detection_event(forged)
    assert not purple_guard.verify_yara_control_event(ctx.lease, ctx.combat, forged)
    assert purple_guard.verify_yara_control_event(ctx.lease, ctx.combat, event)
    assert path.read_bytes() == original and not ctx.combat.list_actions()


def test_read_only_claim_checks_do_not_consume_or_renew_native_deadline(controlled_runtime):
    ctx = controlled_runtime
    _declaration, path, original, event = _capture_sealed_without_attempt(ctx)
    digest = event_proof_digest(event)
    with ctx.detector._receipt_lock:
        proofs = ctx.detector._control_proofs
        before = proofs._receipts[digest]
        metadata = copy.deepcopy(ctx.detector._control_proof_metadata[digest])
    for _ in range(3):
        assert purple_guard.verify_yara_control_event(ctx.lease, ctx.combat, event)
    with ctx.detector._receipt_lock:
        after = proofs._receipts[digest]
        assert after is before
        assert not proofs.verify(event, generation=ctx.detector.lifecycle_generation,
                                 now=before.expires_monotonic, review=metadata)
    assert path.read_bytes() == original and not ctx.combat.list_actions()


@pytest.mark.parametrize("revoke", ["source-epoch", "lease", "producer-graph"])
def test_current_epoch_lease_or_graph_revocation_prevents_original_replay(controlled_runtime, revoke):
    ctx = controlled_runtime
    _declaration, path, original, event = _capture_sealed_without_attempt(ctx)
    if revoke == "source-epoch":
        capability = ctx.detector._redteam_receipt_capability
        ctx.detector.bind_redteam_receipt_capability(None, expected=capability)
    elif revoke == "lease":
        purple_guard.RedTeamValidationLease.release(ctx.lease)
    else:
        ctx.manager.modules[ctx.detector.name] = YaraScannerModule()
    assert not purple_guard.verify_yara_control_event(ctx.lease, ctx.combat, event)
    ctx.bus.publish(event)
    ctx.drain()
    assert path.read_bytes() == original and not ctx.combat.list_actions()
    assert ctx.combat.response_snapshot()["host_authority_verified"] is False


def test_all_declared_controls_are_checked_before_another_control_can_act(controlled_runtime):
    ctx = controlled_runtime
    _declaration, path, original, event = _capture_sealed_without_attempt(ctx)
    ctx.config.adversary_combat_quarantine_files = False
    _other_declaration, other, _other_original = ctx.create_control("archive", step_id="other-control")
    other.write_bytes(b"inert changed object")
    ctx.config.adversary_combat_quarantine_files = True
    assert not purple_guard.verify_yara_control_event(ctx.lease, ctx.combat, event)
    ctx.bus.publish(event)
    ctx.drain()
    assert path.read_bytes() == original and not ctx.combat.list_actions()


def test_terminal_claim_cannot_open_second_transaction_and_public_undo_needs_authority(controlled_runtime):
    ctx = controlled_runtime
    _declaration, path, original = ctx.create_control("text")
    ctx.begin_scan()
    event = _wait_for(lambda: ctx.detection(path), description="actual native control scan did not publish")
    _wait_for(lambda: ctx.response(event), description="control did not commit its first actual transaction")
    first = ctx.combat.list_actions()
    assert len(first) == 1 and first[0]["status"] == "applied"
    assert not purple_guard.verify_yara_control_event(ctx.lease, ctx.combat, event)
    ctx.bus.publish(event)
    ctx.drain()
    assert [row["action_id"] for row in ctx.combat.list_actions()] == [first[0]["action_id"]]
    assert not path.exists()
    ctx.stop_sources()
    assert ctx.combat.undo_action(first[0]["action_id"])["ok"] is False
    assert not path.exists(), "a source canary must not grant public installed Undo"
    assert ctx.undo_exact(first[0]["action_id"])["ok"] is True
    assert path.read_bytes() == original


@pytest.mark.parametrize("fault", ["after-rename", "terminal-journal", "abort-finalizer"])
def test_actual_source_observe_quarantine_fault_restores_exact_object_without_host_authority(
    controlled_runtime, monkeypatch, fault,
):
    ctx = controlled_runtime
    _declaration, path, original = ctx.create_control("text")
    before = path.stat(follow_symlinks=False)
    fault_entered = threading.Event()
    abort_entered = threading.Event()
    pending = {}
    authority_calls = []
    finishes = []
    journal_commit = ctx.combat._journal_commit
    abort = purple_guard.RedTeamValidationLease.abort_marker_containment
    finish = purple_guard.RedTeamValidationLease.finish_yara_containment

    def held_authority():
        authority_calls.append(threading.get_ident())
        return False, "Source Observe rollback regression; host authority remains held"

    def fail_after_actual_rename(action, **_kwargs):
        pending["action"] = action
        assert not path.exists()
        assert Path(action.details["quarantine"]).exists()
        assert action.details["sha256"] == hashlib.sha256(original).hexdigest()
        fault_entered.set()
        raise OSError("inert post-rename fault")

    def fail_first_terminal_journal(action):
        if not fault_entered.is_set():
            pending["action"] = action
            assert not path.exists()
            assert Path(action.details["quarantine"]).exists()
            fault_entered.set()
            raise OSError("inert terminal journal fault")
        return journal_commit(action)

    def refuse_final_abort(lease, combat, target, *, recapture):
        if recapture:
            abort_entered.set()
            raise OSError("inert finalizer abort fault")
        return abort(lease, combat, target, recapture=recapture)

    def observe_real_finish(lease, combat, event, action, *, succeeded):
        finishes.append((event.details["yara_control_claim_id"], succeeded))
        return finish(lease, combat, event, action, succeeded=succeeded)

    monkeypatch.setattr(breach_state, "protect_authority", held_authority)
    monkeypatch.setattr(purple_guard.RedTeamValidationLease,
                        "finish_yara_containment", observe_real_finish)
    if fault == "terminal-journal":
        monkeypatch.setattr(ctx.combat, "_journal_commit", fail_first_terminal_journal)
    else:
        monkeypatch.setattr(ctx.combat, "_commit_after_mutation", fail_after_actual_rename)
    if fault == "abort-finalizer":
        monkeypatch.setattr(purple_guard.RedTeamValidationLease,
                            "abort_marker_containment", refuse_final_abort)
    ctx.begin_scan()
    event = _wait_for(lambda: ctx.detection(path), description="real control event was not observed")
    assert ctx.bus.verify(event) and ctx.detector.verify_detection_event(event)
    assert ctx.detector.verify_control_detection_event(event)
    assert event.details["observed_content_sha256"] == hashlib.sha256(original).hexdigest()
    assert fault_entered.wait(10), "actual quarantine did not reach the injected post-effect boundary"
    ctx.drain()
    assert path.read_bytes() == original
    after = path.stat(follow_symlinks=False)
    assert (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) == (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    assert int(getattr(after, "st_birthtime_ns", 0)) == int(getattr(before, "st_birthtime_ns", 0))
    assert before.st_nlink == after.st_nlink == 1
    assert not Path(pending["action"].details["quarantine"]).exists()
    assert ctx.response(event) is None
    assert not any(row["status"] in {"applied", "recovery_required"}
                   for row in ctx.combat.list_actions())
    assert ctx.combat._mutation_blocked is False
    assert ctx.combat.response_snapshot()["state"] != "RECOVERY REQUIRED"
    assert ctx.combat.response_snapshot()["host_authority_verified"] is False
    assert authority_calls and breach_state.protect_authority()[0] is False
    assert finishes == [(event.details["yara_control_claim_id"], False)]
    assert not purple_guard.verify_yara_control_event(ctx.lease, ctx.combat, event)
    if fault == "abort-finalizer":
        assert abort_entered.is_set(), "the intended throwing finalizer was not exercised"
    ctx.bus.publish(event)
    ctx.drain()
    assert path.read_bytes() == original
    assert finishes == [(event.details["yara_control_claim_id"], False)]
    assert not any(row["status"] in {"applied", "recovery_required"}
                   for row in ctx.combat.list_actions())


def test_reset_during_control_publication_cancellation_preserves_ordinary_worker(
    controlled_runtime, monkeypatch,
):
    ctx = controlled_runtime
    ctx.config.adversary_combat_quarantine_files = False
    _declaration, path, original = ctx.create_control("text")
    request_reset = threading.Event()
    reset_done = threading.Event()
    reset_errors = []
    state = purple_guard._lease_authority(ctx.lease)
    publish = ctx.detector.publish_event

    def reset_plain_issuer_state():
        try:
            if not request_reset.wait(10):
                raise AssertionError("test did not request the owned issuer reset")
            # Actual enrollment reset revokes plain capability/claim metadata.
            # No native scanner, Rules, result, wrapper or native weakref is
            # obtained or disposed on this retained diagnostic thread.
            with state.lock:
                state._reset_native_enrollment()
        except Exception as exc:
            reset_errors.append((type(exc).__name__, str(exc)[:300]))
        finally:
            reset_done.set()

    reset_thread = threading.Thread(target=reset_plain_issuer_state,
                                    name="YaraOwnedIssuerReset")

    def deliver_reset_then_raise(event):
        publish(event)
        if event.details.get("yara_control_claim_id"):
            request_reset.set()
            assert reset_done.wait(10), "actual issuer reset did not complete"
            assert not reset_errors, reset_errors
            raise RuntimeError("inert reset-at-cancel publication fault")

    monkeypatch.setattr(ctx.detector, "publish_event", deliver_reset_then_raise)
    reset_thread.start()
    try:
        ctx.begin_scan()
        original_event = _wait_for(lambda: ctx.detection(path),
                                   description="real original control event was not delivered")
        assert reset_done.wait(10)
        reset_thread.join(10)
        assert not reset_thread.is_alive() and not reset_errors
        _wait_for(lambda: ctx.detector.last_error == "inert reset-at-cancel publication fault",
                  description="cancellation replaced the original fault or stopped the owner")
        ctx.drain()
        assert ctx.bus.verify(original_event)
        assert not purple_guard.verify_yara_control_event(ctx.lease, ctx.combat, original_event)
        assert path.read_bytes() == original and not ctx.combat.list_actions()
        ordinary = ctx.target / "ordinary-after-reset.txt"
        ordinary.write_bytes(MARKER)
        ordinary_event = _wait_for(lambda: ctx.detection(ordinary),
                                   description="real ordinary scanner did not continue after reset")
        ctx.drain()
        assert ctx.bus.verify(ordinary_event)
        assert ctx.detector.verify_detection_event(ordinary_event)
        assert ordinary_event.details["observed_content_sha256"] == hashlib.sha256(MARKER).hexdigest()
        assert ordinary_event.details["response_authorized"] is False
        assert not ordinary_event.details.get("yara_control_claim_id")
        assert ctx.detector._thread.is_alive() and ctx.detector.status == "running"
        assert ctx.detector.last_error == "inert reset-at-cancel publication fault"
        assert path.read_bytes() == original and ordinary.read_bytes() == MARKER
        assert not ctx.combat.list_actions()
        assert ctx.combat.response_snapshot()["host_authority_verified"] is False
    finally:
        request_reset.set()
        reset_thread.join(10)
        assert not reset_thread.is_alive(), "owned issuer reset thread did not retire"


def test_cancellation_after_actual_rename_keeps_truthful_commit_and_blocks_future_replay(
    controlled_runtime, monkeypatch,
):
    ctx = controlled_runtime
    _declaration, path, original = ctx.create_control("text")
    commit_entered = threading.Event()
    release_commit = threading.Event()
    publication_raised = threading.Event()
    pending = {}
    commit = ctx.combat._commit_after_mutation
    publish = ctx.detector.publish_event

    def held_commit(action, **kwargs):
        pending["action"] = action
        commit_entered.set()
        assert release_commit.wait(10), "test did not release the owned partial-publication transaction"
        return commit(action, **kwargs)

    def deliver_then_raise(event):
        publish(event)
        if event.details.get("yara_control_claim_id"):
            assert commit_entered.wait(10), "actual worker did not reserve/move before injected publication error"
            publication_raised.set()
            raise RuntimeError("inert post-delivery publication fault")

    monkeypatch.setattr(ctx.combat, "_commit_after_mutation", held_commit)
    monkeypatch.setattr(ctx.detector, "publish_event", deliver_then_raise)
    try:
        ctx.begin_scan()
        event = _wait_for(lambda: ctx.detection(path), description="control publication was not delivered")
        assert commit_entered.wait(10) and publication_raised.wait(10)
        # Wait until _scan_file processed the publication error and cancelled
        # future admission, not merely until the injecting hook raised.
        _wait_for(lambda: "inert post-delivery publication fault" in ctx.detector.last_error,
                  description="native producer did not finish phase-aware publication cancellation")
        assert not path.exists()
        assert not purple_guard.verify_yara_control_event(ctx.lease, ctx.combat, event)
        release_commit.set()
        ctx.drain()
        response = _wait_for(lambda: ctx.response(event),
                             description="already authorized exact effect was not truthfully committed")
        assert response.details["postcondition_verified"] is True
        assert response.details["actions"] == ["quarantine_file"]
        rows = ctx.combat.list_actions()
        assert len(rows) == 1 and rows[0]["status"] == "applied"
        assert rows[0]["action_id"] == pending["action"].action_id
        assert rows[0]["target"] == str(path)
        assert rows[0]["details"]["sha256"] == hashlib.sha256(original).hexdigest()
        assert rows[0]["details"]["terminal_object_sha256"] == hashlib.sha256(original).hexdigest()
        assert not path.exists()
        assert ctx.combat._mutation_blocked is False
        assert ctx.combat.response_snapshot()["host_authority_verified"] is False
        before = {row["action_id"] for row in rows}
        ctx.bus.publish(event)
        ctx.drain()
        assert {row["action_id"] for row in ctx.combat.list_actions()} == before
        assert not purple_guard.verify_yara_control_event(ctx.lease, ctx.combat, event)
        # Release the issuer's exclusive moved-object witness before a second
        # Windows file open; all live receipt/replay assertions remain above.
        ctx.stop_sources()
        assert Path(rows[0]["details"]["quarantine"]).read_bytes() == original
    finally:
        release_commit.set()
