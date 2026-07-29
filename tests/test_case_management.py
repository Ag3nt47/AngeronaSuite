import json
import threading

import pytest

from angerona.core.case_management import (
    CaseConflict, CaseStore, EvidenceReference,
)


KEY = b"c" * 32


def evidence(name="../unsafe/raw.bin"):
    return EvidenceReference(
        "ev-1", name, "a" * 64, 12, "sensor", "signed event",
        100, "sensitive",
    )


def test_optimistic_case_versioning_and_attributed_comments(tmp_path):
    store = CaseStore(tmp_path / "cases.db", KEY)
    case = store.create_case("Incident", tags=("malware",), now=100)
    updated = store.update_case(
        case.case_id, case.version, status="investigating", assignee="analyst"
    )
    assert updated.version == 2
    with pytest.raises(CaseConflict):
        store.update_case(case.case_id, case.version, status="closed")
    store.add_comment(case.case_id, "analyst-1", "Reviewed evidence", now=101)
    exported = json.loads(store.export_sanitized(case.case_id))
    assert exported["timeline"][0]["actor"] == "analyst-1"
    store.close()


def test_evidence_is_reference_only_safe_named_and_chain_authenticated(tmp_path):
    store = CaseStore(tmp_path / "cases.db", KEY)
    case = store.create_case("Incident")
    store.add_evidence(case.case_id, evidence(), "collector", now=100)
    store.transfer_custody("ev-1", "reviewed", "analyst", now=101)
    assert store.verify_custody("ev-1")
    exported = json.loads(store.export_sanitized(case.case_id))
    assert exported["raw_evidence_included"] is False
    assert exported["evidence_references"][0]["display_name"] == "raw.bin"
    store._db.execute("UPDATE custody SET action='tampered' WHERE evidence_id='ev-1'")
    assert not store.verify_custody("ev-1")
    store.close()


def test_legal_hold_prevents_retention_deletion(tmp_path):
    store = CaseStore(tmp_path / "cases.db", KEY)
    held = store.create_case("Held", retention_until=10)
    store.update_case(held.case_id, held.version, legal_hold=True)
    expired = store.create_case("Expired", retention_until=10)
    assert store.purge_expired(now=20) == 1
    assert store.get_case(held.case_id).legal_hold
    with pytest.raises(KeyError):
        store.get_case(expired.case_id)
    store.close()


def test_concurrent_updates_allow_only_one_version_winner(tmp_path):
    store = CaseStore(tmp_path / "cases.db", KEY)
    case = store.create_case("Concurrent")
    outcomes = []
    barrier = threading.Barrier(3)

    def update(status):
        barrier.wait()
        try:
            store.update_case(case.case_id, 1, status=status)
            outcomes.append("ok")
        except CaseConflict:
            outcomes.append("conflict")

    threads = [
        threading.Thread(target=update, args=("investigating",)),
        threading.Thread(target=update, args=("contained",)),
    ]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()
    assert sorted(outcomes) == ["conflict", "ok"]
    store.close()


def test_sanitized_export_redacts_content_and_excludes_restricted(tmp_path):
    store = CaseStore(tmp_path / "cases.db", KEY)
    case = store.create_case(
        "sk-live-secret alice@example.com",
        assignee="alice@example.com",
        tags=("Password=hunter2",),
    )
    store.add_comment(case.case_id, "analyst", "Bearer eyJsecret Password=hunter2")
    restricted = EvidenceReference(
        "ev-secret", "secret.txt", "b" * 64, 9,
        r"C:\Users\Alice\secret.txt", "token=abcdef123456",
        100, "restricted",
    )
    store.add_evidence(case.case_id, restricted, "collector")
    raw = store.export_sanitized(case.case_id).decode()
    for secret in (
        "sk-live-secret", "alice@example.com", "hunter2",
        r"C:\\Users\\Alice\\secret.txt", "eyJsecret", "abcdef123456",
    ):
        assert secret not in raw
    value = json.loads(raw)
    assert value["privacy_manifest"]["restricted_references"] == "excluded"
    assert value["evidence_references"] == []
    assert value["timeline"][0]["text"] == "[COMMENT EXCLUDED]"
    store.close()


def test_custody_head_detects_suffix_truncation_and_retention_is_receipted(tmp_path):
    store = CaseStore(tmp_path / "cases.db", KEY)
    case = store.create_case("Incident", retention_until=10)
    store.add_evidence(case.case_id, evidence(), "collector", now=1)
    store.transfer_custody("ev-1", "reviewed", "analyst", now=2)
    assert store.verify_custody("ev-1")
    newest = store._db.execute(
        "SELECT MAX(seq) FROM custody WHERE evidence_id='ev-1'"
    ).fetchone()[0]
    store._db.execute("DELETE FROM custody WHERE seq=?", (newest,))
    assert not store.verify_custody("ev-1")
    store.close()

    store = CaseStore(tmp_path / "retention.db", KEY)
    case = store.create_case("Expired", retention_until=10)
    store.add_evidence(case.case_id, evidence(), "collector", now=1)
    assert store.purge_expired(now=20) == 1
    assert store.verify_retention_receipt("ev-1")
    store._db.execute(
        "UPDATE retention_receipts SET event_count=99 WHERE evidence_id='ev-1'"
    )
    assert not store.verify_retention_receipt("ev-1")
    store.close()
