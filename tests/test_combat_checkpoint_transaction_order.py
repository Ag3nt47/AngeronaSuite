"""Credential admission precedes durable phases; later faults remain held.

All state and effects are disposable fixtures. No firewall or process command
is issued, and the protected-store fixture preserves its transaction boundary.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import threading

import pytest
from test_breach_lockdown import FakeFirewall, installed_protect_for_inert_combat
from angerona.core.response_contract import authorize_response

from angerona.core import secure_store
from angerona.core.eventbus import Event, Severity
from angerona.modules.adversary_combat import AdversaryCombat, JournalIntegrityError


def _fixture(tmp_path, monkeypatch, *, fake_anchor=False):
    (tmp_path / "bus.key").write_text((b"k" * 32).hex(), encoding="ascii")
    protected = tmp_path / "secrets.dpapi"
    protected.write_bytes(b"inert protected-store fixture")
    values = {"UNRELATED_SECRET": "must survive"}
    monkeypatch.setattr(secure_store, "read_secret_values", lambda names, *_a, **_k: {
        key: values[key] for key in names if key in values
    })

    def write(updates, root):
        with secure_store.secret_transaction(root):
            values.update(updates)
            protected.write_text(json.dumps(values), encoding="utf-8")
            return protected

    monkeypatch.setattr(secure_store, "write_secret_map", write)
    module = AdversaryCombat(tmp_path, rollback_anchor={} if fake_anchor else None)
    module._read_journal(strict=True)
    initial = _action(module)
    module._journal_intent(initial)
    module._journal_failure(initial, "inert fixture; no module was started")
    return module, values


def _action(module):
    return module._action(
        "activate_honeypots", "Smart Deception",
        Event("Adversary Combat", "inert fixture", Severity.INFO),
        "startup", reversible=True, details={"module": "Smart Deception"},
    )


def _authority(module):
    return {path: path.read_bytes() for path in (
        module.receipt_path, module.data_root / "secrets.dpapi",
        module.recovery_witness_path, module.data_root / "bus.key",
    )}


def test_busy_credential_admission_preserves_all_authority_and_retry_works(
    tmp_path, monkeypatch,
):
    module, values = _fixture(tmp_path, monkeypatch)
    before = _authority(module)
    original = module._read_recovery_anchor_value()
    attempted = []

    @contextmanager
    def busy(_root):
        attempted.append(True)
        raise TimeoutError("Credential store transaction is busy; credentials were not changed")
        yield  # pragma: no cover - contextmanager must refuse before entry

    with monkeypatch.context() as patch:
        patch.setattr(secure_store, "secret_transaction", busy)
        with pytest.raises(JournalIntegrityError):
            module._journal_intent(_action(module))

    assert attempted == [True]
    assert _authority(module) == before
    assert module._read_recovery_anchor_value() == original
    module._journal_intent(_action(module))
    records, legacy = module._read_journal(strict=True)
    assert not legacy and len(records) == 3
    assert module._recovery_anchor(allow_create=False)["last_journal_sequence"] == 3
    assert values["UNRELATED_SECRET"] == "must survive"
    assert (module.data_root / "bus.key").read_bytes() == before[module.data_root / "bus.key"]


@pytest.mark.parametrize("fault", ["protected_write", "witness_write"])
def test_failure_after_durable_append_keeps_original_authority_and_hold(
    tmp_path, monkeypatch, fault,
):
    module, _values = _fixture(tmp_path, monkeypatch)
    before = _authority(module)
    with monkeypatch.context() as patch:
        if fault == "protected_write":
            patch.setattr(secure_store, "write_secret_map", lambda *_a, **_k: (
                _ for _ in ()).throw(OSError("inert protected-store write fault")))
        else:
            patch.setattr(module, "_write_recovery_witness", lambda _anchor: (
                _ for _ in ()).throw(OSError("inert witness write fault")))
        with pytest.raises(JournalIntegrityError):
            module._journal_intent(_action(module))

    journal = module.receipt_path.read_bytes()
    assert journal.startswith(before[module.receipt_path])
    assert len(journal.splitlines()) == 3
    assert module.recovery_witness_path.read_bytes() == before[module.recovery_witness_path]
    assert (module.data_root / "bus.key").read_bytes() == before[module.data_root / "bus.key"]
    if fault == "protected_write":
        assert (module.data_root / "secrets.dpapi").read_bytes() == before[module.data_root / "secrets.dpapi"]
    with pytest.raises(JournalIntegrityError):
        module._read_journal(strict=True)
    assert not module._reconcile_state()
    assert module._mutation_blocked and module._journal_error
    after_failure = _authority(module)
    with pytest.raises(JournalIntegrityError):
        module._journal_intent(_action(module))
    assert _authority(module) == after_failure


def test_private_fake_anchor_needs_no_protected_store_transaction(tmp_path, monkeypatch):
    module, _values = _fixture(tmp_path, monkeypatch, fake_anchor=True)

    @contextmanager
    def forbidden(_root):
        pytest.fail("An in-memory anchor must not acquire the protected store")
        yield  # pragma: no cover

    monkeypatch.setattr(secure_store, "secret_transaction", forbidden)
    module._journal_intent(_action(module))
    records, legacy = module._read_journal(strict=True)
    assert not legacy and len(records) == 3


def test_nested_journal_writer_holds_credential_transaction_through_witness(
    tmp_path, monkeypatch,
):
    module, _values = _fixture(tmp_path, monkeypatch)
    observed = []
    original_append = module._append_pinned_journal_bytes
    original_witness = module._write_recovery_witness

    def append(encoded):
        secure_store._assert_transaction(tmp_path)
        observed.append("append")
        return original_append(encoded)

    def witness(anchor):
        secure_store._assert_transaction(tmp_path)
        observed.append("witness")
        return original_witness(anchor)

    monkeypatch.setattr(module, "_append_pinned_journal_bytes", append)
    monkeypatch.setattr(module, "_write_recovery_witness", witness)
    action = _action(module)
    with module._journaled_mutation(action):
        module._journal_commit(action)

    assert observed == ["append", "witness", "append", "witness"]
    records, legacy = module._read_journal(strict=True)
    assert not legacy and len(records) == 4
    assert records[-1]["record_type"] == "commit"
    assert module._recovery_anchor(allow_create=False)["last_journal_sequence"] == 4


def test_host_intent_busy_refuses_effect_without_latching_and_later_request_can_run(
    tmp_path, monkeypatch,
):
    module, _values = _fixture(tmp_path, monkeypatch)
    before = _authority(module)
    effects = []
    firewall = FakeFirewall()
    def query(arguments, **kwargs):
        if arguments[:2] == ["firewall", "add"]:
            effects.append(arguments)
        return firewall.query(arguments, **kwargs)
    monkeypatch.setattr(module, "_lockdown_query", query)
    monkeypatch.setattr(module, "_lockdown_effective_policy_query", firewall.policy_query)
    event = Event("Inert Detector", "fixture", Severity.HIGH,
                  details={"active_attack": True, **authorize_response(["isolate_host"], local_host=True)})

    @contextmanager
    def busy(_root):
        raise TimeoutError("Credential store transaction is busy; credentials were not changed")
        yield  # pragma: no cover

    with monkeypatch.context() as patch:
        patch.setattr(secure_store, "secret_transaction", busy)
        assert module._isolate_host(event, "combat-aaaaaaaaaaaa") is None

    assert effects == [] and _authority(module) == before
    assert not module._mutation_blocked
    result = module._isolate_host(event, "combat-bbbbbbbbbbbb")
    assert result is not None and result.status == "applied"
    assert len(effects) == 2 and not module._mutation_blocked
    records, legacy = module._read_journal(strict=True)
    assert not legacy and len(records) == 4
    assert [record["record_type"] for record in records[-2:]] == ["intent", "commit"]


def test_real_bounded_local_credential_contention_precedes_append(tmp_path, monkeypatch):
    module, _values = _fixture(tmp_path, monkeypatch)
    before = _authority(module)
    admitted, release = threading.Event(), threading.Event()
    errors = []

    def holder():
        try:
            with secure_store.secret_transaction(tmp_path):
                admitted.set()
                if not release.wait(5):
                    raise AssertionError("Inert credential holder was not released")
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=holder, name="inert-credential-holder")
    worker.start()
    try:
        assert admitted.wait(2)
        with pytest.raises(JournalIntegrityError):
            module._journal_intent(_action(module))
    finally:
        release.set()
        worker.join(timeout=3)
    assert not worker.is_alive() and not errors
    assert _authority(module) == before
    records, legacy = module._read_journal(strict=True)
    assert not legacy and len(records) == 2


def test_undo_intent_failure_retains_only_typed_cause_and_preserves_hold(
    tmp_path, monkeypatch,
):
    module, _values = _fixture(tmp_path, monkeypatch)
    emitted = []
    secret = "inert-sensitive-token-must-not-appear"

    def fail_undo_intent(*_args, **_kwargs):
        try:
            raise TimeoutError(secret)
        except TimeoutError as exc:
            raise JournalIntegrityError("inert wrapper " + secret) from exc

    monkeypatch.setattr(module, "_append_undo_phase", fail_undo_intent)
    monkeypatch.setattr(module, "_undo_record", lambda _record: pytest.fail(
        "An uncommitted undo intent must never authorize a host action"))
    monkeypatch.setattr(module, "emit", lambda message, severity, **details: emitted.append(
        {"message": message, "severity": severity, "details": details}))
    action = _action(module)
    module._journal_intent(action)
    module._rollback_uncertain_reversible_mutation(
        action, "inert uncertain fixture", release_custody=lambda: None,
    )

    assert module._mutation_blocked and action.action_id in module._recovery_required
    assert len(emitted) == 1 and emitted[0]["severity"] == Severity.CRITICAL
    details = emitted[0]["details"]
    assert details["recovery_error"] == "uncertain mutation rollback intent was not durable"
    assert details["recovery_cause_types"] == ["JournalIntegrityError", "TimeoutError"]
    assert details["response_authorized"] is False and details["recovery_required"] is True
    assert secret not in json.dumps(emitted)
    records, legacy = module._read_journal(strict=True)
    assert not legacy and records[-1]["record_type"] == "orphan"
