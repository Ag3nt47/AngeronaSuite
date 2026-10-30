"""Recorder byte commitments and independent append-only authority fixtures."""
from __future__ import annotations

from dataclasses import asdict, replace
import itertools
import json
import sqlite3
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from angerona.core.independent_high_water import HighWaterRejected, HighWaterUnavailable
from angerona.core.eventbus import BusAuthority, Event, Severity
from angerona.core.personal_sentinel_authority import (
    Ed25519PrivateSigner, HmacSha256Authenticator, InProcessSentinelTransport,
    PersonalSentinelAuthority, PersonalSentinelAuthorityClient, SentinelStateIntegrityError,
)
from angerona.core.recorder_epoch import (
    MAX_EPOCH_ROWS, MAX_ROW_BYTES, ZERO, EpochClaim, EpochRejected, admit_successor,
    canonical, claim_rows, commit_rows, issue_receipt, parse_claim, parse_receipt, rows_root, verify_receipt,
    verify_row_range,
)


INSTALL = "a" * 32
INSTANCE = "b" * 32
NOW = 1_800_000_000.0


def row(row_id=1, *, message="event", details='{"x":1}', hmac_sig="c" * 64):
    return (row_id, NOW, "Fixture", 2, message, details, hmac_sig)


@pytest.fixture
def stack(tmp_path):
    auth = Ed25519PrivateSigner(Ed25519PrivateKey.generate(), key_id="request-only")
    signer = Ed25519PrivateSigner(Ed25519PrivateKey.generate(), key_id="remote-only")
    authority = PersonalSentinelAuthority(tmp_path / "authority.json", installation_id=INSTALL,
        client_instance_id=INSTANCE, request_verifier=auth.public_verifier(), response_signer=signer,
        response_verifier=signer.public_verifier(), enable_recorder_epochs=True,
        max_nonces=64, clock=lambda: NOW)
    serial = itertools.count(1)
    client = PersonalSentinelAuthorityClient(installation_id=INSTALL, client_instance_id=INSTANCE,
        request_signer=auth, response_verifier=signer.public_verifier(),
        transport=InProcessSentinelTransport(authority, test_only=True), allow_test_transport=True,
        clock=lambda: NOW, nonce_factory=lambda: f"{next(serial):043d}")
    try:
        yield auth, signer, authority, client
    finally:
        authority.close()


def test_exact_row_bytes_include_details_whitespace_and_hmac_but_grant_no_producer_trust():
    original = commit_rows((row(),))
    assert rows_root(original) != rows_root(commit_rows((row(details='{"x": 1}'),)))
    assert rows_root(original) != rows_root(commit_rows((row(hmac_sig="d" * 64),)))
    # Unsigned legacy rows can be byte-committed, without turning them into
    # authenticated producer records or replacing their original representation.
    assert commit_rows((row(hmac_sig=""),))


@pytest.mark.parametrize("rows", [(), (row(2), row(1)), (row(1), row(1)),
    ((True, NOW, "x", 30, "m", "{}", "sig"),),
    ((1, float("nan"), "x", 30, "m", "{}", "sig"),),
    (row(message="x" * (MAX_ROW_BYTES + 1)),)],
    ids=["empty", "reordered", "duplicate", "bool-id", "nonfinite", "oversize"])
def test_ambiguous_rows_cannot_receive_an_epoch_commitment(rows):
    with pytest.raises(EpochRejected):
        commit_rows(rows)


def test_iterator_count_bound_and_root_order_cannot_be_bypassed():
    with pytest.raises(EpochRejected):
        commit_rows(row(i) for i in range(1, MAX_EPOCH_ROWS + 2))
    rows = commit_rows((row(1), row(2)))
    with pytest.raises(EpochRejected):
        rows_root(tuple(reversed(rows)))


def test_signed_epoch_round_trip_and_strict_successor_persist(stack):
    _auth, signer, authority, client = stack
    assert client.read_recorder_head() is None
    first = client.append_recorder_epoch(claim_rows(commit_rows((row(1), row(2))), current=None))
    verify_receipt(first, signer.public_verifier(), installation_id=INSTALL, client_instance_id=INSTANCE)
    second = client.append_recorder_epoch(claim_rows(commit_rows((row(3),)), current=first))
    assert second.claim.previous_receipt == first.digest()
    assert second.claim.epoch == 2 and client.read_recorder_head() == second
    stored = json.loads(authority.state_path.read_bytes())
    assert stored["recorder_epoch_head"] == asdict(second)
    assert parse_receipt(asdict(first)) == first


def test_current_request_credential_cannot_rewrite_previously_sealed_row_range(stack):
    _stolen_request_auth, _signer, _authority, client = stack
    first = client.append_recorder_epoch(claim_rows(commit_rows((row(1), row(2))), current=None))
    # Even an authenticated client issuing a higher epoch cannot replace the
    # old range: the authority enforces both predecessor and disjoint row IDs.
    rewritten = EpochClaim(2, 1, 2, 2, rows_root(commit_rows((row(1, message="forged"), row(2)))), first.digest())
    with pytest.raises(HighWaterRejected):
        client.append_recorder_epoch(rewritten)
    assert client.read_recorder_head() == first


def test_host_request_private_key_cannot_forge_independently_signed_archive(stack):
    auth, signer, _authority, client = stack
    first = client.append_recorder_epoch(claim_rows(commit_rows((row(),)), current=None))
    # The attacker knows the public signing format and holds the legitimate
    # request private key. Sign the correct archival body, claiming the
    # authority's key ID, so this tests the independent cryptographic key.
    forged = replace(first, claim=replace(first.claim, rows_root="e" * 64))
    forged = replace(forged, signature=auth.sign(b"Angerona-Recorder-Epoch-v1\0" + canonical(forged.body())))
    with pytest.raises(EpochRejected):
        verify_receipt(forged, signer.public_verifier(), installation_id=INSTALL, client_instance_id=INSTANCE)
    changed = replace(first, claim=replace(first.claim, rows_root="d" * 64))
    with pytest.raises(EpochRejected):
        verify_receipt(changed, signer.public_verifier(), installation_id=INSTALL, client_instance_id=INSTANCE)


def test_duplicate_fork_overlap_and_skipped_epoch_do_not_replace_head(stack):
    _auth, _signer, _authority, client = stack
    first = client.append_recorder_epoch(claim_rows(commit_rows((row(),)), current=None))
    second = claim_rows(commit_rows((row(2),)), current=first)
    for bad in (first.claim, replace(second, previous_receipt="d" * 64),
                replace(second, first_id=1), replace(second, epoch=3)):
        with pytest.raises(HighWaterRejected):
            client.append_recorder_epoch(bad)
    assert client.read_recorder_head() == first


def test_reply_loss_after_durable_append_reconciles_from_fresh_signed_read(stack):
    _auth, _signer, _authority, client = stack
    original = client.transport
    class LoseReply:
        def exchange(self, body):
            original.exchange(body)
            raise OSError("fixture reply loss after server commit")
    client.transport = LoseReply()
    claim = claim_rows(commit_rows((row(),)), current=None)
    with pytest.raises(HighWaterUnavailable):
        client.append_recorder_epoch(claim)
    client.transport = original
    assert client.read_recorder_head().claim == claim


def test_enabled_authority_restarts_without_rebaselining_older_receipt(stack):
    auth, signer, authority, client = stack
    first = client.append_recorder_epoch(claim_rows(commit_rows((row(),)), current=None))
    authority.close()
    restarted = PersonalSentinelAuthority(authority.state_path, installation_id=INSTALL, client_instance_id=INSTANCE,
        request_verifier=auth.public_verifier(), response_signer=signer, response_verifier=signer.public_verifier(),
        enable_recorder_epochs=True, clock=lambda: NOW, max_nonces=64)
    client.transport = InProcessSentinelTransport(restarted, test_only=True)
    try:
        assert client.read_recorder_head() == first
    finally:
        restarted.close()


def test_hmac_only_authority_cannot_enable_archival_receipt_signing(tmp_path):
    auth = HmacSha256Authenticator(b"k" * 32)
    with pytest.raises(ValueError, match="independent Ed25519"):
        PersonalSentinelAuthority(tmp_path / "state.json", installation_id=INSTALL, client_instance_id=INSTANCE,
                                  authenticator=auth, enable_recorder_epochs=True)


def test_feature_is_explicit_and_old_server_refuses_extended_state(stack):
    auth, signer, authority, client = stack
    client.append_recorder_epoch(claim_rows(commit_rows((row(),)), current=None))
    authority.close()
    disabled = PersonalSentinelAuthority(authority.state_path, installation_id=INSTALL, client_instance_id=INSTANCE,
        request_verifier=auth.public_verifier(), response_signer=signer, response_verifier=signer.public_verifier(),
        clock=lambda: NOW, max_nonces=64)
    client.transport = InProcessSentinelTransport(disabled, test_only=True)
    try:
        with pytest.raises((HighWaterRejected, HighWaterUnavailable, SentinelStateIntegrityError)):
            client.read_recorder_head()
    finally:
        disabled.close()


def test_receipt_shape_cannot_hide_extra_fields_or_signature_encoding_alias(stack):
    _auth, _signer, _authority, client = stack
    receipt = client.append_recorder_epoch(claim_rows(commit_rows((row(),)), current=None))
    with pytest.raises(EpochRejected):
        parse_receipt({**asdict(receipt), "allow_rewrite": True})
    with pytest.raises(EpochRejected):
        parse_receipt({**asdict(receipt), "signature": receipt.signature + "=="})
    with pytest.raises(EpochRejected):
        parse_claim({**asdict(receipt.claim), "epoch": True})
    with pytest.raises(EpochRejected):
        admit_successor(EpochClaim(1, 2, 2, 1, "e" * 64, ZERO), receipt)


def test_actual_stored_rows_changed_and_retagged_with_stolen_key_fail_archival_check(stack):
    _auth, signer, _authority, client = stack
    stolen_bus_authority = BusAuthority(b"s" * 32)
    original_event = Event("Fixture", "event", Severity.MEDIUM, ts=NOW, details={"x": 1})
    original_mac = stolen_bus_authority.sign(original_event)
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE events (id INTEGER, ts REAL, module TEXT, severity INTEGER, message TEXT, details TEXT, hmac_sig TEXT)")
        db.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?)",
                       (row(1, hmac_sig=original_mac), row(2, hmac_sig=original_mac)))
        original = tuple(db.execute("SELECT * FROM events ORDER BY id"))
        commitments = commit_rows(original)
        receipt = client.append_recorder_epoch(claim_rows(commitments, current=None))
        original_result = verify_row_range(receipt, commitments, original, signer.public_verifier(),
                                           installation_id=INSTALL, client_instance_id=INSTANCE)
        assert original_result.state == "verified-stored-bytes"
        assert original_result.independently_current is False
        # An attacker can recompute this host MAC, but not the independent
        # historical Ed25519 receipt or its committed per-row digest index.
        rewritten_event = replace(original_event, message="forged history")
        new_mac = stolen_bus_authority.sign(rewritten_event)
        assert stolen_bus_authority.verify(replace(rewritten_event, hmac_sig=new_mac))
        db.execute("UPDATE events SET message=?, hmac_sig=? WHERE id=1", ("forged history", new_mac))
        actual = tuple(db.execute("SELECT * FROM events ORDER BY id"))
        result = verify_row_range(receipt, commitments, actual, signer.public_verifier(),
                                  installation_id=INSTALL, client_instance_id=INSTANCE)
        assert result.state == "record-mismatch" and result.changed_rows == 1 and result.verified_rows == 1
        with pytest.raises(EpochRejected):
            verify_row_range(receipt, commit_rows(actual), actual, signer.public_verifier(),
                              installation_id=INSTALL, client_instance_id=INSTANCE)


def test_severity_retention_holes_remain_loss_and_surviving_row_changes_still_detected(stack):
    _auth, signer, _authority, client = stack
    rows = (row(1), row(2), row(3))
    index = commit_rows(rows)
    receipt = client.append_recorder_epoch(claim_rows(index, current=None))
    missing = verify_row_range(receipt, index, (row(1), row(3)), signer.public_verifier(),
                               installation_id=INSTALL, client_instance_id=INSTANCE)
    assert missing.state == "rows-unavailable" and missing.missing_rows == 1 and missing.verified_rows == 2
    changed = verify_row_range(receipt, index, (row(1, message="forged"), row(3)), signer.public_verifier(),
                               installation_id=INSTALL, client_instance_id=INSTANCE)
    assert changed.state == "record-mismatch" and changed.missing_rows == changed.changed_rows == 1
    empty = verify_row_range(receipt, index, (), signer.public_verifier(),
                             installation_id=INSTALL, client_instance_id=INSTANCE)
    assert empty.state == "rows-unavailable" and empty.missing_rows == 3


def test_shared_client_serializes_exchanges_before_monotonic_reply_floor(stack):
    _auth, _signer, _authority, client = stack
    original = client.transport
    entered, release, second_entered, second_attempted = (threading.Event() for _ in range(4))
    calls, failures, results = [], [], []
    class DelayedFirstReply:
        def exchange(self, body):
            calls.append(threading.get_ident())
            response = original.exchange(body)
            if len(calls) == 1:
                entered.set()
                assert release.wait(3)
            else:
                second_entered.set()
            return response
    client.transport = DelayedFirstReply()
    def read(second=False):
        if second:
            second_attempted.set()
        try:
            results.append(client.read_recorder_head())
        except BaseException as exc:
            failures.append(exc)
    first, second = threading.Thread(target=read), threading.Thread(target=lambda: read(True))
    try:
        first.start()
        assert entered.wait(2)
        second.start()
        assert second_attempted.wait(2)
        assert not second_entered.wait(0.1)
        release.set()
    finally:
        release.set()
        for worker in (first, second):
            if worker.ident is not None:
                worker.join(3)
                assert not worker.is_alive()
    assert not failures and results == [None, None] and len(calls) == 2


def test_different_key_ids_cannot_hide_reused_request_and_archival_key(tmp_path):
    private = Ed25519PrivateKey.generate()
    request = Ed25519PrivateSigner(private, key_id="host-request")
    authority = Ed25519PrivateSigner(private, key_id="independent-authority-name")
    with pytest.raises(ValueError, match="cryptographically distinct"):
        PersonalSentinelAuthority(tmp_path / "state.json", installation_id=INSTALL, client_instance_id=INSTANCE,
            request_verifier=request.public_verifier(), response_signer=authority,
            response_verifier=authority.public_verifier(), enable_recorder_epochs=True)
    assert not (tmp_path / "state.json").exists()


@pytest.mark.parametrize("kind", ["hmac", "opaque"])
def test_archival_enrollment_refuses_opaque_or_shared_mac_request_verifier(tmp_path, kind):
    signer = Ed25519PrivateSigner(Ed25519PrivateKey.generate(), key_id="remote-only")
    class Opaque:
        key_id = "opaque"
        def verify(self, _payload, _signature):
            return True
    request = HmacSha256Authenticator(b"r" * 32) if kind == "hmac" else Opaque()
    with pytest.raises(ValueError, match="independent Ed25519"):
        PersonalSentinelAuthority(tmp_path / "state.json", installation_id=INSTALL, client_instance_id=INSTANCE,
            request_verifier=request, response_signer=signer, response_verifier=signer.public_verifier(),
            enable_recorder_epochs=True)


def test_signature_bound_precedes_decoder_allocation(stack, monkeypatch):
    from angerona.core import recorder_epoch
    _auth, _signer, _authority, client = stack
    receipt = client.append_recorder_epoch(claim_rows(commit_rows((row(),)), current=None))
    calls = []
    monkeypatch.setattr(recorder_epoch.base64, "b64decode", lambda *a, **k: calls.append(a) or b"")
    with pytest.raises(EpochRejected):
        parse_receipt({**asdict(receipt), "signature": "x" * 1_000_000})
    assert not calls


def test_malformed_none_row_is_not_misclassified_as_missing_range(stack):
    _auth, signer, _authority, client = stack
    index = commit_rows((row(),))
    receipt = client.append_recorder_epoch(claim_rows(index, current=None))
    with pytest.raises(EpochRejected):
        verify_row_range(receipt, index, (None,), signer.public_verifier(),
                          installation_id=INSTALL, client_instance_id=INSTANCE)
