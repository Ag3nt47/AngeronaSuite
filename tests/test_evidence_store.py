import time

import pytest

from angerona.core.eventbus import Event, Severity
from angerona.core.evidence_store import (
    EvidenceEnvelope,
    EvidenceStore,
    HuntPredicate,
    HuntQuery,
)


def _item(event_id: str, *, ts: float, source: str = "local",
          category: str = "process", severity: int = 2,
          message: str = "PowerShell started") -> EvidenceEnvelope:
    return EvidenceEnvelope(
        event_id=event_id, observed_at=ts, category=category,
        activity="start", severity=severity, message=message,
        module="Process Monitor", source=source, confidence=80,
        device={"id": "host-1"},
        subject={"kind": "process", "id": "1234"},
        attributes={"pid": 1234},
        provenance={"kind": "sensor"},
    )


def test_event_normalization_is_versioned_stable_and_preserves_provenance():
    event = Event(
        module="DNS", message="lookup", severity=Severity.HIGH, ts=123.5,
        details={"domain": "example.invalid", "confidence": 91},
        hmac_sig="abc",
    )
    one = EvidenceEnvelope.from_event(event)
    two = EvidenceEnvelope.from_event(event)
    assert one.event_id == two.event_id
    assert one.schema_version == "1.0"
    assert one.subject["domain"] == "example.invalid"
    assert one.provenance["integrity"] == "hmac"


def test_store_is_idempotent_local_only_and_row_bounded(tmp_path):
    now = time.time()
    with EvidenceStore(tmp_path / "evidence.db", max_rows=2) as store:
        assert store.append(_item("a", ts=now))
        assert not store.append(_item("a", ts=now))
        store.append(_item("b", ts=now + 1))
        store.append(_item("c", ts=now + 2))
        assert store.count() == 2
        with pytest.raises(ValueError, match="remote evidence"):
            store.append(_item("remote", ts=now, source="remote"))


def test_batch_append_is_transactional_and_counts_duplicates(tmp_path):
    now = time.time()
    with EvidenceStore(tmp_path / "evidence.db", max_rows=20) as store:
        inserted, duplicates = store.append_many([
            _item("a", ts=now), _item("a", ts=now),
            _item("b", ts=now + 1),
        ])
        assert (inserted, duplicates) == (2, 1)
        assert store.count() == 2
        with pytest.raises(ValueError, match="remote evidence"):
            store.append_many([
                _item("local", ts=now),
                _item("remote", ts=now, source="remote"),
            ])
        assert store.count() == 2


def test_age_retention_is_enforced(tmp_path):
    now = time.time()
    with EvidenceStore(
        tmp_path / "evidence.db", retention_seconds=60, max_rows=20
    ) as store:
        store.append(_item("old", ts=now - 120))
        store.append(_item("new", ts=now))
        store.enforce_retention(now=now)
        result = store.hunt(HuntQuery(limit=10))
        assert [item.event_id for item in result.evidence] == ["new"]


def test_structured_hunt_filters_and_never_accepts_sql(tmp_path):
    now = time.time()
    with EvidenceStore(tmp_path / "evidence.db") as store:
        store.append(_item("one", ts=now, severity=3, message="Encoded PowerShell"))
        store.append(_item(
            "two", ts=now + 1, category="network", severity=1,
            message="Browser connection",
        ))
        query = HuntQuery(predicates=(
            HuntPredicate("category", "eq", "process"),
            HuntPredicate("message", "contains", "powershell"),
            HuntPredicate("device.id", "eq", "host-1"),
        ), limit=5)
        result = store.hunt(query)
        assert [item.event_id for item in result.evidence] == ["one"]
        assert result.scanned <= 50
        with pytest.raises(ValueError, match="unsupported hunt field"):
            HuntPredicate("1=1; DROP TABLE normalized_evidence", "eq", "x")


def test_query_and_envelope_limits_are_validated():
    with pytest.raises(ValueError, match="limit"):
        HuntQuery(limit=1001)
    with pytest.raises(ValueError, match="at most"):
        HuntQuery(predicates=tuple(
            HuntPredicate("module", "eq", str(i)) for i in range(13)
        ))
    with pytest.raises(ValueError, match="256 KiB"):
        EvidenceEnvelope(
            event_id="large", observed_at=1, category="file", activity="write",
            severity=1, message="x", module="test",
            attributes={"blob": "x" * (300 * 1024)},
        )
