import json
import sqlite3

import pytest

import angerona.core.case_management as case_management
from angerona.core.case_management import (
    CaseStore,
    ObservableIntegrityError,
)


KEY = b"o" * 32


def _cases(store: CaseStore, count: int = 2):
    return [store.create_case(f"Case {index}") for index in range(count)]


def test_observable_add_is_typed_bounded_and_idempotent(tmp_path, monkeypatch):
    store = CaseStore(tmp_path / "cases.db", KEY)
    case = store.create_case("Incident")

    first = store.add_observable(
        case.case_id, "domain", "Example.COM.", status="suggested",
        confidence=0.75, source="analyst", observable_id="obs-first", now=10,
    )
    duplicate = store.add_observable(
        case.case_id, "domain", "example.com", status="approved",
        confidence=1.0, source="another-source", observable_id="obs-duplicate",
    )
    assert duplicate == first
    assert duplicate.status == "suggested"
    assert duplicate.confidence == 0.75
    assert duplicate.source == "analyst"
    assert len(store.observables(case.case_id)) == 1

    for kind, value in (
        ("unknown", "thing"),
        ("ipv4", "2001:db8::1"),
        ("file_sha256", "not-a-hash"),
        ("process_name", "folder/bad.exe"),
        ("url", "file:///private/file"),
    ):
        with pytest.raises(ValueError):
            store.add_observable(case.case_id, kind, value)
    with pytest.raises(ValueError):
        store.add_observable(case.case_id, "domain", "valid.example", confidence=1.1)

    monkeypatch.setattr(case_management, "MAX_OBSERVABLES", 1)
    with pytest.raises(ValueError, match="bound"):
        store.add_observable(case.case_id, "ipv4", "192.0.2.1")
    # Duplicate adds stay idempotent even after the case reaches its bound.
    assert store.add_observable(case.case_id, "domain", "EXAMPLE.COM").observable_id == (
        "obs-first"
    )
    store.close()


def test_only_reviewed_included_observables_correlate_cases(tmp_path):
    store = CaseStore(tmp_path / "cases.db", KEY)
    left, right = _cases(store)
    suggested = store.add_observable(
        left.case_id, "ipv4", "192.0.2.10", status="suggested",
        source="local suggestion",
    )
    store.add_observable(
        right.case_id, "ipv4", "192.0.2.10", status="approved",
        source="verified sensor",
    )
    assert store.related_cases(left.case_id) == ()

    reviewed = store.review_observable(suggested.observable_id, status="approved")
    assert reviewed.status == "approved"
    related = store.related_cases(left.case_id)
    assert related[0].case_id == right.case_id
    assert related[0].shared_observables == 1
    assert related[0].shared_types == ("ipv4",)

    store.review_observable(
        suggested.observable_id, status="approved", exclude_from_similarity=True
    )
    assert store.related_cases(left.case_id) == ()
    store.close()


def test_sanitized_export_contains_counts_but_no_observable_secrets(tmp_path):
    store = CaseStore(tmp_path / "cases.db", KEY)
    case = store.create_case("Sensitive indicators")
    secret = "alice.private+incident@example.com"
    store.add_observable(
        case.case_id, "email", secret, status="suggested", confidence=0.9,
        source=r"C:\Users\Alice\private-source.txt",
        exclude_from_similarity=True,
    )
    raw = store.export_sanitized(case.case_id).decode("utf-8")
    assert secret not in raw
    assert "private-source" not in raw
    # Neither a raw nor normalized value, nor an HMAC correlation key, is exported.
    assert "similarity_hmac" not in raw
    value = json.loads(raw)
    assert value["raw_observables_included"] is False
    assert value["observable_summary"] == [{
        "type": "email",
        "status": "suggested",
        "count": 1,
        "excluded_from_similarity_count": 1,
    }]
    store.close()


def test_keyed_similarity_index_is_key_separated_and_tamper_evident(tmp_path):
    one = CaseStore(tmp_path / "one.db", b"1" * 32)
    two = CaseStore(tmp_path / "two.db", b"2" * 32)
    case_one = one.create_case("One")
    case_two = two.create_case("Two")
    record = one.add_observable(
        case_one.case_id, "domain", "sensitive.example", status="approved"
    )
    two.add_observable(
        case_two.case_id, "domain", "sensitive.example", status="approved"
    )
    digest_one = one._db.execute(
        "SELECT similarity_hmac FROM case_observables"
    ).fetchone()[0]
    digest_two = two._db.execute(
        "SELECT similarity_hmac FROM case_observables"
    ).fetchone()[0]
    assert digest_one != digest_two
    assert "sensitive.example" not in digest_one

    one._db.execute(
        "UPDATE case_observables SET raw_value='attacker.example' "
        "WHERE observable_id=?", (record.observable_id,)
    )
    assert not one.verify_observable(record.observable_id)
    with pytest.raises(ObservableIntegrityError):
        one.observables(case_one.case_id)
    exported = json.loads(one.export_sanitized(case_one.case_id))
    assert exported["observable_summary"] == []
    assert exported["observable_integrity_failures_excluded"] == 1
    one.close()
    two.close()


def test_tampered_suggestion_cannot_be_promoted_into_similarity(tmp_path):
    store = CaseStore(tmp_path / "cases.db", KEY)
    left, right = _cases(store)
    suggestion = store.add_observable(
        left.case_id, "process_name", "suspicious.exe", status="suggested"
    )
    store.add_observable(
        right.case_id, "process_name", "suspicious.exe", status="approved"
    )
    store._db.execute(
        "UPDATE case_observables SET status='approved' WHERE observable_id=?",
        (suggestion.observable_id,),
    )
    assert not store.verify_observable(suggestion.observable_id)
    assert store.related_cases(left.case_id) == ()
    store.close()


def test_related_case_results_and_retention_are_bounded(tmp_path, monkeypatch):
    store = CaseStore(tmp_path / "cases.db", KEY)
    cases = _cases(store, 5)
    for case in cases:
        store.add_observable(
            case.case_id, "file_sha256", "a" * 64, status="approved"
        )
    assert len(store.related_cases(cases[0].case_id, limit=2)) == 2
    monkeypatch.setattr(case_management, "MAX_RELATED_CASES", 1)
    assert len(store.related_cases(cases[0].case_id, limit=9999)) == 1

    expiring = store.create_case("Expiring", retention_until=10)
    store.add_observable(expiring.case_id, "ipv6", "2001:0db8::1")
    assert store.purge_expired(now=20) == 1
    assert store._db.execute(
        "SELECT COUNT(*) FROM case_observables WHERE case_id=?",
        (expiring.case_id,),
    ).fetchone()[0] == 0
    store.close()


def test_existing_case_database_migrates_in_place(tmp_path):
    path = tmp_path / "legacy.db"
    db = sqlite3.connect(path)
    db.execute(
        "CREATE TABLE cases(case_id TEXT PRIMARY KEY,title TEXT,status TEXT,"
        "assignee TEXT,tags_json TEXT,version INTEGER,legal_hold INTEGER,"
        "retention_until REAL,created_at REAL,updated_at REAL)"
    )
    db.execute(
        "INSERT INTO cases VALUES('case-legacy','Legacy','open','','[]',1,0,0,1,1)"
    )
    db.commit()
    db.close()

    store = CaseStore(path, KEY)
    observable = store.add_observable(
        "case-legacy", "ipv4", "198.51.100.9", status="approved"
    )
    assert observable.case_id == "case-legacy"
    assert store.verify_observable(observable.observable_id)
    store.close()
